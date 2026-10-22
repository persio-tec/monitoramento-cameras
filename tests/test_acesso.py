"""Testes do túnel SSH, das contas por aparelho e do link de acesso.

Não cria contas do sistema, não chama o pkexec e não mexe no Tailscale.
Rodar a partir da raiz do projeto: python3 -m unittest discover -s tests
"""
import base64
import importlib.util
import socketserver
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("mod", RAIZ / "main.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class SemRedirecionamento(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class TestNomeEChave(unittest.TestCase):
    def test_nome_com_espaco_vira_underline(self):
        self.assertEqual(mod.nome_usuario_aparelho("Meu Celular", []), "cam_meu_celular")

    def test_colisao_recebe_sufixo(self):
        self.assertEqual(mod.nome_usuario_aparelho("x", ["cam_x"]), "cam_x_2")

    def test_nome_vazio_tem_fallback(self):
        self.assertEqual(mod.nome_usuario_aparelho("  ", []), "cam_aparelho")

    def test_nome_enorme_e_truncado(self):
        self.assertTrue(len(mod.nome_usuario_aparelho("A" * 80, [])) <= 36)

    def test_usuario_invalido_e_recusado_antes_de_pedir_senha(self):
        for nome in ["", "Com Maiuscula", "com espaco", "x" * 40, "ok-1"]:
            with self.subTest(nome=nome):
                with self.assertRaises(ValueError):
                    mod.criar_usuario_ssh_sistema(nome, "senha123456")

    def test_senha_invalida_e_recusada(self):
        with self.assertRaises(ValueError):
            mod.criar_usuario_ssh_sistema("teste", "123")
        with self.assertRaises(ValueError):
            mod.criar_usuario_ssh_sistema("teste", "com:dois")

    def test_senha_aleatoria_sem_separadores(self):
        senhas = {mod.senha_ssh_aleatoria(16) for _ in range(50)}
        self.assertEqual(len(senhas), 50)
        self.assertTrue(all(len(s) == 16 and ":" not in s for s in senhas))

    def test_linha_authorized_keys_restrita(self):
        linha = mod.linha_authorized_keys()
        self.assertTrue(linha.startswith("restrict,port-forwarding,permitopen="))
        self.assertIn('permitopen="127.0.0.1:*"', linha)

    def test_script_falha_no_primeiro_erro_e_rejeita_hifen(self):
        script = mod.SCRIPT_USUARIO_SSH
        self.assertIn("set -euo pipefail", script)
        self.assertIn("[a-z_][a-z0-9_]{0,31}", script)
        self.assertNotIn("0-9_-]", script)


class TestTunelSSH(unittest.TestCase):
    def test_montar_comando_com_chave_antes_do_destino(self):
        comando = mod.montar_comando_ssh(
            "cam_celular@192.168.200.12", 8766, chave="~/.ssh/id_ed25519_cam_celular"
        )
        self.assertIn("-i ~/.ssh/id_ed25519_cam_celular", comando)
        self.assertLess(comando.index("-i"), comando.index("cam_celular@"))

    def test_analisar_comando_colado(self):
        resultado = mod.analisar_comando_ssh(
            "ssh -p 2222 -L 9000:127.0.0.1:8766 usuario@servidor"
        )
        self.assertEqual(resultado, ("usuario@servidor:2222", 9000, None))

    def test_analisar_com_chave(self):
        resultado = mod.analisar_comando_ssh(
            "ssh -i ~/.ssh/k -L 8766:127.0.0.1:8766 root@10.0.0.5"
        )
        self.assertEqual(resultado, ("root@10.0.0.5", 8766, "~/.ssh/k"))

    def test_texto_que_nao_e_ssh(self):
        self.assertIsNone(mod.analisar_comando_ssh("apenas um host"))
        self.assertIsNone(mod.analisar_comando_ssh(""))


class TestServidorComToken(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.token = mod.carregar_ou_criar_token()
        cls.senha = "senha-de-teste-123"

        class ServidorLivre(mod.ServidorCameras):
            def __init__(self, cameras, senha, token):
                self.cameras = cameras
                self.senha = senha
                self.token = token
                self.parar = threading.Event()
                socketserver.TCPServer.__init__(
                    self, ("127.0.0.1", 0), mod.ManipuladorCameras
                )

        cls.servidor = ServidorLivre({}, cls.senha, cls.token)
        cls.base = f"http://127.0.0.1:{cls.servidor.server_address[1]}"
        threading.Thread(target=cls.servidor.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.servidor.shutdown()
        cls.servidor.server_close()

    def abrir(self, caminho, headers=None, seguir=True):
        req = urllib.request.Request(self.base + caminho, headers=headers or {})
        opener = urllib.request.build_opener() if seguir else urllib.request.build_opener(SemRedirecionamento)
        return opener.open(req, timeout=5)

    def test_sem_credencial_recusa(self):
        with self.assertRaises(urllib.error.HTTPError) as erro:
            self.abrir("/")
        self.assertEqual(erro.exception.code, 401)

    def test_login_basico_entra(self):
        cred = base64.b64encode(f"camera:{self.senha}".encode()).decode()
        self.assertEqual(self.abrir("/", {"Authorization": f"Basic {cred}"}).status, 200)

    def test_token_na_url_grava_cookie_httponly(self):
        with self.assertRaises(urllib.error.HTTPError) as erro:
            self.abrir(f"/?acesso={self.token}", seguir=False)
        self.assertEqual(erro.exception.code, 302)
        cookie = erro.exception.headers.get("Set-Cookie", "")
        self.assertIn(f"cam_acesso={self.token}", cookie)
        self.assertIn("HttpOnly", cookie)

    def test_token_errado_recusa(self):
        with self.assertRaises(urllib.error.HTTPError) as erro:
            self.abrir("/?acesso=token-errado")
        self.assertEqual(erro.exception.code, 401)

    def test_cookie_valido_entra_e_invalido_recusa(self):
        ok = self.abrir("/", {"Cookie": f"cam_acesso={self.token}"})
        self.assertEqual(ok.status, 200)
        with self.assertRaises(urllib.error.HTTPError) as erro:
            self.abrir("/", {"Cookie": "cam_acesso=lixo"})
        self.assertEqual(erro.exception.code, 401)


class TestAparelhos(unittest.TestCase):
    def test_lista_de_aparelhos_em_arquivo_temporario(self):
        import tempfile

        original = mod.ARQUIVO_APARELHOS
        with tempfile.TemporaryDirectory() as pasta:
            mod.ARQUIVO_APARELHOS = Path(pasta) / "aparelhos.json"
            try:
                mod.salvar_aparelhos([{"nome": "Celular", "usuario": "cam_celular", "senha": "s", "chave": "/k"}])
                self.assertEqual(mod.carregar_aparelhos()[0]["usuario"], "cam_celular")
                self.assertEqual(oct(mod.ARQUIVO_APARELHOS.stat().st_mode & 0o777), "0o600")
                mod.ARQUIVO_APARELHOS.write_text("nao e json", encoding="utf-8")
                self.assertEqual(mod.carregar_aparelhos(), [])
            finally:
                mod.ARQUIVO_APARELHOS = original


if __name__ == "__main__":
    unittest.main()
