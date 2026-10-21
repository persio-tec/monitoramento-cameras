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
- **Conectar ao NVR** — digite o IP (ou nome) do gravador NVR/DVR/XVR no campo
  **NVR**, clique em **Conectar ao NVR** e informe o usuário e a senha do
  gravador. O app fala com o NVR via ONVIF e lista todos os canais dele no
  campo "Câmera" (ex.: `Canal 1: Camera 01`). Escolha o canal e clique em
  **Adicionar câmera de rede**: o endereço RTSP do canal (por exemplo
  `/Streaming/Channels/101` nos Hikvision) é descoberto sozinho e vai junto
  com as credenciais, sem precisar montar a URL na mão. Também funciona com
  NVRs que exigem autenticação no RTSP.
- **ID da câmera** + **Localizar na rede** — informe o ID/serial da câmera
  (aquele número no rótulo/etiqueta dela), o IP (`192.168.0.10`), um nome de
  host (`camera-sala`) ou uma URL completa, e clique em **Localizar na rede**.
  O app confirma que a câmera responde, verifica as portas RTSP e diz se ela
  fala ONVIF, preenchendo o campo "Câmera" com o resultado.
- **Buscar pelo ID do CMS (UID)** — para câmeras que só aparecem no software
  CMS (XMEYE, Yoosee, Dahua Configuração, etc.): digite o ID/UID delas no
  campo **ID da câmera** e clique no botão. O app varre a rede local pelas
  portas típicas de CMS/DVR (9530, 5050, 34567, 37777, 8000) e ainda confere
  se o ID bate com o número de série que a câmera publica no ONVIF — os
  aparelhos em que o ID confere são listados primeiro, marcados com
  "ID confere". Os achados entram no campo "Câmera" com a porta RTSP certa
  (554 ou 8554) e vão para **Adicionar câmera de rede**. Obs.: o CMS encontra
  a câmera pela internet (P2P); essa busca só acha câmeras que estão ligadas
  na mesma rede deste computador.
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

## Privacidade e dados locais

O pacote do aplicativo (o `.exe`, o `.app` ou o zip baixado) **não contém dados
pessoais**. Ele carrega apenas o programa e a lista pública de marcas/caminhos
RTSP (`cameras_db.json` e `cameras_ip_wifi_mundial.json`). Não existe nenhuma
senha, endereço IP, nome de câmera ou conta sua dentro do arquivo distribuído.

Tudo que é pessoal é criado **na máquina em que o aplicativo é aberto**, na
primeira execução:

| Item | Onde fica | O que é |
|---|---|---|
| `senha-web.txt` | pasta de dados do usuário | senha do servidor web, gerada automaticamente |
| `senha-seguranca.txt` | pasta de dados do usuário | hash PBKDF2 da senha de segurança |
| `capturas/` | pasta ao lado do aplicativo | suas fotos e vídeos |

A pasta de dados do usuário é `~/.local/share/monitoramento-cameras/` no Linux e
no macOS, e `C:\Users\<usuário>\.local\share\monitoramento-cameras\` no Windows.
Os dois arquivos de senha são criados com permissão restrita ao usuário local
(`0600`) e a pasta com `0700`.

Consequências práticas ao instalar em **outro computador**:

- As senhas **não viajam**: o app gera uma nova senha web e pede para você criar
  uma nova senha de segurança (12+ caracteres) na primeira abertura.
- A **lista de câmeras não é salva em arquivo** — ela vive apenas na sessão
  aberta. No PC novo, adicione as câmeras de novo ou use **Configurar
  automaticamente (ONVIF)**.
- A pasta `capturas/` começa vazia.
- O acesso pelo celular depende do **Tailscale instalado e logado na conta
  daquele computador**. Em outra máquina, o endereço `<hostname>.ts.net` exibido
  será o daquela máquina; sem o Tailscale logado, o acesso remoto não funciona.

Copiar manualmente a pasta de dados entre computadores levaria as senhas junto —
evite: é mais seguro deixar cada máquina gerar as suas.

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
