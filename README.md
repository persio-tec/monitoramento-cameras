# Monitoramento local por câmeras

Aplicativo desktop para visualizar câmeras USB ou webcams conectadas ao
computador, tirar fotos e gravar vídeos. O processamento é local. O servidor
web transmite vídeo somente pelo endereço privado da VPN Tailscale, com senha;
não abre uma porta pública na internet.

## Abrir

Abra **Monitoramento por Câmeras** no menu de aplicativos ou execute:

```sh
/usr/sbin/python3 /home/persio/Projetos/monitoramento-cameras/main.py
```

Adicione uma câmera pelo índice (normalmente `0` para a câmera padrão). Fotos e
vídeos são salvos na pasta `capturas`, ao lado deste arquivo.

### Câmeras de rede (Wi-Fi/LAN)

No quadro **Câmeras na rede local (Wi-Fi)**:

- **Configurar automaticamente (ONVIF)** — descobre as câmeras sozinho na rede
  (WS-Discovery), pede o usuário e a senha uma única vez e já adiciona cada
  câmera com o endereço RTSP correto. É o jeito mais rápido quando as câmeras
  são ONVIF (a maioria das IP cams é). Deixe o usuário em branco para tentar
  câmeras sem senha.
- **ID da câmera** + **Localizar na rede** — informe o ID/serial da câmera
  (aquele número no rótulo/etiqueta dela), o IP (`192.168.0.10`), um nome de
  host (`camera-sala`) ou uma URL completa, e clique em **Localizar na rede**.
  O app confirma que a câmera responde, verifica as portas RTSP e diz se ela
  fala ONVIF, preenchendo o campo "Câmera" com o resultado.
- **Buscar na rede** — procura câmeras com porta RTSP aberta (554/8554) na
  mesma sub-rede. Escolha o IP encontrado, ajuste o caminho RTSP (padrão
  `/stream1`; Hikvision usa `/Streaming/Channels/101`, Dahua
  `/cam/realmonitor?channel=1&subtype=0`) e clique em **Adicionar câmera de
  rede**.
- Câmeras com autenticação também podem ser adicionadas digitando a URL
  completa no campo "Câmera":
  `rtsp://usuario:senha@192.168.0.10:554/stream1`. O campo aceita qualquer IP
  ou URL, mesmo quando a busca não encontra nada.

## Ver as câmeras no celular

1. Conecte este computador e o celular à mesma rede privada Tailscale, usando a
   mesma conta.
2. Abra o aplicativo neste computador e adicione a câmera que deseja visualizar.
3. Aguarde o link `https://<hostname>.ts.net` aparecer na seção
   **Acesso seguro pelo celular (HTTPS + Tailscale)**. Na primeira vez, clique
   em **Ativar certificado HTTPS** para autorizar o Tailscale Serve; se a
   página não abrir sozinha, o endereço de autorização fica exibido na janela.
4. Clique em **Autorizar e mostrar login e senha** e informe a senha de
   segurança (criada na primeira vez, com pelo menos 12 caracteres) para
   revelar o login `camera` e a senha gerada. Os dados ficam visíveis por
   60 segundos.
5. No celular, com o Tailscale conectado, copie o link e abra-o no navegador,
   informando o login e a senha quando solicitado.

O servidor web escuta apenas em `127.0.0.1:8766` e é exposto no endereço
privado pelo Tailscale Serve, com certificado HTTPS. O link só fica disponível
enquanto o aplicativo está aberto e o Tailscale está conectado. A senha é
gerada automaticamente e guardada apenas neste computador em
`~/.local/share/monitoramento-cameras/senha-web.txt`; a senha de segurança fica
em `~/.local/share/monitoramento-cameras/senha-seguranca.txt` como hash
PBKDF2, e os dois arquivos têm acesso restrito ao usuário local. Se já existir
outra configuração do Tailscale Serve, o aplicativo não a altera. Não encaminhe
a porta `8766` no roteador nem publique o link fora da sua rede privada.

## Requisitos

- Linux com sessão gráfica e acesso a uma webcam ou câmera USB
- Python 3 com Tkinter
- OpenCV (`cv2`) e Pillow
- Tailscale conectado neste computador e no celular para acesso remoto

## Gerar instalador para Windows/macOS/Linux

### Opção 1: GitHub Actions (mais fácil, sem instalar Wine)
1. Suba este repositório para o GitHub
2. Vá em `Actions > Build Multi-Platform > Run workflow`
3. Baixe os artefatos: `MonitoramentoCameras-Windows.zip`, `MonitoramentoCameras-macOS.dmg`, `MonitoramentoCameras-Linux`

### Opção 2: Localmente

**Windows (PowerShell/CMD):**
```bat
build_windows.bat
```
O arquivo fica em `dist\MonitoramentoCameras.exe`

**macOS/Linux:**
```bash
chmod +x build_unix.sh
./build_unix.sh
```
No macOS gera `dist/MonitoramentoCameras.app`. No Linux gera `dist/MonitoramentoCameras` (executável). 

**Manual:**
```bash
pip install -r requirements.txt pyinstaller
pyinstaller monitoramento-cameras.spec
```

### Notas
- No Windows, pode aparecer aviso do SmartScreen na primeira vez (normal para apps sem certificado)
- No macOS, se bloqueado: `xattr -d com.apple.quarantine MonitoramentoCameras.app`
- Precisa ter `libGL1` no Linux se for rodar em ambiente minimalista
- Para abrir portas/firewall não é necessário (só usa localhost + Tailscale)
