# Monitoramento local por câmeras

Aplicativo desktop para visualizar câmeras USB ou webcams conectadas ao
computador, tirar fotos e gravar vídeos. O processamento é local. O servidor
web transmite vídeo somente pelo endereço privado da VPN Tailscale, com senha;
não abre uma porta pública na internet. Também dá para assistir de outro
computador ou celular por um túnel SSH, sem depender de VPN.

## Abrir

Abra **Monitoramento por Câmeras** no menu de aplicativos ou execute:

```sh
/usr/sbin/python3 /home/persio/Projetos/monitoramento-cameras/main.py
```

Adicione uma câmera pelo índice (normalmente `0` para a câmera padrão). Fotos e
vídeos são salvos na pasta `capturas`, ao lado deste arquivo.

### Câmeras de rede (Wi-Fi/LAN)

No quadro **Câmeras na rede local (Wi-Fi)**:

- **Configurar automaticamente (ONVIF + Rede)** — descobre as câmeras sozinho na rede
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

Sem Tailscale, use o túnel SSH (seção seguinte) — o servidor web continua
ligado em `127.0.0.1` de qualquer forma, só não é exposto fora da máquina.

## Ver as câmeras sem VPN (túnel SSH)

Dá para ver as mesmas telas do navegador sem Tailscale, usando um túnel SSH
(port forwarding). O app já mantém o servidor web ligado em `127.0.0.1:8766`
(só escuta na máquina, nunca na internet) e monta o comando para você.

1. Abra o app no computador/servidor onde estão as câmeras e procure o quadro
   **Acesso remoto por túnel SSH**.
2. Em **Servidor SSH**, ponha o destino: `usuario@192.168.0.10` (ou só
   `192.168.0.10`, ou `usuario@host:2222` se o SSH do servidor usa outra porta).
   Em **Porta local** escolha a porta que o túnel vai abrir no computador que
   vai assistir (padrão `8766`). Se essa porta já estiver ocupada pelo próprio
   app, ele usa `8767` e avisa.
3. Clique em **Copiar comando**. No computador/celular que vai **assistir**,
   cole e rode no terminal:

   ```sh
   ssh -N -o ExitOnForwardFailure=yes -L 8766:127.0.0.1:8766 usuario@192.168.0.10
   ```

   O terminal fica "ocupado" — é o túnel funcionando. Para encerrar, `Ctrl+C`.
4. Nesse mesmo computador/celular, abra `http://127.0.0.1:8766` no navegador e
   entre com o login `camera` e a senha do app (veja **Autorizar e mostrar login
   e senha**).

   **Dica**: o botão **Copiar link** (no quadro do túnel) copia a URL já com o
   token de acesso: `http://127.0.0.1:8766/?acesso=...`. Quem abre esse link
   entra direto, sem janela de login. O mesmo vale para o link do Tailscale.

O app precisa estar aberto no computador/servidor das câmeras durante a sessão.
O túnel é criptografado pelo próprio SSH, inclusive em rede pública (Wi-Fi de
cafeteria, 4G): não é preciso abrir porta no roteador nem configurar Tailscale.

### Celular

- **Android**: Termux (`pkg install openssh`) ou um app de SSH (JuiceSSH,
  Termius).
- **iPhone/iPad**: Termius, Blink Shell ou o app Atalhos (ação "Executar script
  por SSH").
- No celular a página pede o login e a senha do app na primeira visita — a
  menos que você use o link com token.

### Câmera que só responde através de SSH

A mesma técnica serve para uma câmera ou NVR que fica em outra rede. No
computador que alcança a câmera, encaminhe a porta RTSP:

```sh
ssh -N -L 554:192.168.0.10:554 usuario@servidor
```

Depois, no app, use o campo **Câmera** com o IP local do túnel, por exemplo
`rtsp://usuario:senha@127.0.0.1:554/stream1` (o caminho RTSP depende do
fabricante: `/Streaming/Channels/101` na Hikvision,
`/cam/realmonitor?channel=1&subtype=0` na Dahua, `/live/ch00_0` na Yoosee).

### Conta e senha do SSH

O quadro **Acesso remoto por túnel SSH** tem um par de campos **Usuário SSH** e
**Senha**, com os botões **Gerar senha**, **Criar/atualizar usuário** e
**Copiar senha**.

- **Gerar senha** preenche uma senha aleatória (16 caracteres, sem `:`).
- **Criar/atualizar usuário** cria a conta no sistema (ou troca a senha de uma
  conta existente) e instala a chave pública dela em
  `~/.ssh/authorized_keys`. Como criar conta exige privilégio de administrador,
  o app chama o `pkexec` e o **sistema** abre a janela de autorização: é você
  que digita a senha de administrador, e o aplicativo nunca a vê.
- A chave autorizada fica restrita:
  `restrict,port-forwarding,permitopen="127.0.0.1:*"` — sem PTY, sem
  encaminhamento de agente e só pode abrir túnel para o `127.0.0.1` do próprio
  servidor.

### Um aparelho, uma conta (revogue sem afetar os outros)

O quadro **Aparelhos com acesso SSH** dá uma conta, uma senha e uma chave
**por aparelho** (celular, notebook, tablet...). Cada linha da lista tem:

| Botão | O que faz |
|---|---|
| **Gerar senha** | senha aleatória para o aparelho que está sendo cadastrado |
| **Criar aparelho** | cria a conta (`cam_<nome>`), define a senha e gera o par de chaves |
| **Copiar chave privada** | leva a chave privada para a área de transferência, para colar no Termius/Termux (grave com permissão `600`) |
| **Copiar senha** | leva a senha do aparelho selecionado |
| **Usar no túnel** | põe o usuário e a chave do aparelho no quadro do túnel SSH |
| **Copiar comando** | monta e copia o comando `ssh -N -L ...` já com esse usuário e essa chave |
| **Remover aparelho** | apaga a conta do sistema: aquele aparelho perde o acesso na hora, os outros continuam |

Os dados ficam em `~/.local/share/monitoramento-cameras/aparelhos.json`
(permissão `0600`) e as chaves em `~/.ssh/id_ed25519_cam_<nome>` (privada em
`0600`).

Exemplo — celular `Celular` vira a conta `cam_celular`:

```sh
ssh -N -o ExitOnForwardFailure=yes -L 8766:127.0.0.1:8766 -i ~/.ssh/id_ed25519_cam_celular cam_celular@192.168.200.12
```

### Entrar sem senha (chave SSH)

Nesta máquina já existe uma chave só para o acesso às câmeras:
`~/.ssh/id_ed25519_cameras` (privada) e `~/.ssh/id_ed25519_cameras.pub`. A
chave pública já está autorizada em `~/.ssh/authorized_keys` com restrições:
sem PTY, sem encaminhamento de agente e só pode encaminhar portas para o
`127.0.0.1` do próprio servidor.

Para usar em outro computador ou no celular:

1. Copie o arquivo **privado** `id_ed25519_cameras` para o aparelho que vai
   assistir (Android: Termius/Termux; iPhone: Termius), com permissão `600`.
2. No quadro do túnel SSH, preencha:
   - **Servidor SSH**: `persio@192.168.200.12` (mesma rede) ou
     `persio@100.102.107.24` (pela tailnet do Tailscale);
   - **Chave SSH**: `~/.ssh/id_ed25519_cameras`.
3. Clique em **Copiar comando** e rode no outro aparelho:

   ```sh
   ssh -N -o ExitOnForwardFailure=yes -L 8766:127.0.0.1:8766 -i ~/.ssh/id_ed25519_cameras persio@192.168.200.12
   ```

   Dessa vez o SSH não pede senha.

Mais seguro ainda: gerar a chave **no próprio celular** (`ssh-keygen -t ed25519`
no Termux/Termius) e autorizar a chave pública `.pub` em
`~/.ssh/authorized_keys` desta máquina — assim a chave privada nunca sai do
aparelho.

### Link de acesso (sem login no navegador)

Além do login `camera` + senha, o servidor aceita um **token de acesso**:
`~/.local/share/monitoramento-cameras/token-acesso.txt` (permissão `0600`).

Abrindo `http://127.0.0.1:8766/?acesso=TOKEN` (ou o link do Tailscale com o
mesmo parâmetro), o servidor responde `302`, grava um cookie e o navegador
entra direto — sem a janela de login. É o mesmo nível de acesso que a senha,
então **trate o link como segredo**: ele dá acesso às câmeras.

O botão **Copiar link** já copia a URL com o token embutido.

## Copiar e colar

O app tem botões de copiar/colar e menu de contexto (botão direito) em todos
os campos de texto:

- **Colar** (quadro do túnel SSH): cola o destino. Aceita `usuario@host`,
  `host:porta` e até um comando `ssh ...` já pronto — nesse caso o app
  reconhece o usuário, o host, a porta do SSH (`-p`) e a porta local do túnel
  (`-L`) e preenche os campos sozinho.
- **Copiar comando**: leva o comando do túnel para a área de transferência. O
  conteúdo continua lá depois de fechar o app.
- **Copiar URL RTSP**: copia a URL montada da câmera escolhida (para abrir em
  outro player, por exemplo no VLC).
- **Colar URL RTSP**: cola uma URL `rtsp://usuario:senha@ip:porta/caminho` e
  já adiciona a câmera, sem precisar decifrar nada no campo de texto.
- **Botão direito** em qualquer campo: Copiar, Colar, Selecionar tudo, Limpar.

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
| `token-acesso.txt` | pasta de dados do usuário | token do link de acesso (entra sem digitar login) |
| `aparelhos.json` | pasta de dados do usuário | nome, usuário, senha e chave de cada aparelho com acesso SSH |
| `criar-usuario-ssh.sh` | pasta de dados do usuário | script auxiliar que o `pkexec` executa como root |
| `capturas/` | pasta ao lado do aplicativo | suas fotos e vídeos |

A pasta de dados do usuário é `~/.local/share/monitoramento-cameras/` no Linux e
no macOS, e `C:\Users\<usuário>\.local\share\monitoramento-cameras\` no Windows.
Os dois arquivos de senha são criados com permissão restrita ao usuário local
(`0600`) e a pasta com `0700`. O mesmo vale para o token de acesso e para o
`aparelhos.json`.

As chaves SSH dos aparelhos ficam em `~/.ssh/id_ed25519_cam_<nome>` (privada em
`0600`); a senha de cada aparelho fica dentro do `aparelhos.json`, no mesmo
nível de proteção da senha do servidor web.

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
- OpenCV (`cv2`), Pillow e `qrcode` (`pip install opencv-python pillow "qrcode[pil]"`)
- Tailscale conectado neste computador e no celular para acesso remoto
- Cliente SSH (`ssh`) no computador ou celular que vai assistir, se usar o
  túnel SSH em vez da VPN
- `ssh-keygen` e `pkexec` (já presentes em qualquer desktop Linux) para criar
  as chaves e as contas de acesso por aparelho

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
