# ✍️ Assinar o `MonitoramentoCameras.exe` (grátis, open source)

O Windows mostra "Windows protected your PC" (SmartScreen) em programas que não
têm assinatura digital. Assinar o `.exe` elimina esse aviso. O **SignPath**
faz isso **grátis para projetos open source** — o certificado vem da
[Certum](https://signpath.org/), uma autoridade reconhecida pelo Windows.

O workflow `.github/workflows/build.yml` já está pronto: quando o SignPath
estiver configurado, ele gera **duas** versões do programa no build:

| Artefato | Assinado? |
|---|---|
| `MonitoramentoCameras-Windows` | não (o de sempre) |
| `MonitoramentoCameras-Windows-Assinado` | ✅ sim |

Enquanto os dados do SignPath não forem preenchidos, o build continua funcionando
exatamente como antes — nada quebra.

---

## Passo 1 — Conta no SignPath (1 vez só)

1. Abra <https://signpath.io/> e clique em **Sign up**.
2. Use sua conta GitHub (mais rápido) e confirme o e-mail.
3. Escolha o plano **Open Source** (grátis). O SignPath vai pedir o link do
   seu repositório público no GitHub como prova.

> **Importante:** o repositório precisa ser **público** no GitHub para o plano
> open source. O seu já é: <https://github.com/persio/monitoramento-cameras>

## Passo 2 — Criar o projeto e a política de assinatura (1 vez só)

Dentro do painel do SignPath:

1. **Projects → Add project**
   - Nome: `monitoramento-cameras`
   - Copie o **Project slug** (algo como `monitoramento-cameras`).
2. **Policies → Add signing policy**
   - Nome: `release-signing`
   - Copie o **Signing policy slug**.
3. Anote também o **Organization ID** (canto superior direito do painel).

## Passo 3 — Criar o token de API (1 vez só)

1. No painel do SignPath: **API Tokens → Add API token**.
2. Dê um nome (ex.: `github-actions`) e copie o token gerado.
   Ele só aparece uma vez — guarde.

## Passo 4 — Colocar os dados no GitHub (1 vez só)

Abra <https://github.com/persio/monitoramento-cameras/settings/secrets/actions>
e preencha:

### Secreto (aba **Secrets** → **New repository secret**)

| Nome | Valor |
|---|---|
| `SIGNPATH_API_TOKEN` | o token do Passo 3 |

### Variável (aba **Variables** → **New repository variable**)

| Nome | Valor |
|---|---|
| `SIGNPATH_ORGANIZATION_ID` | o Organization ID do Passo 2 |
| `SIGNPATH_PROJECT_SLUG` | o Project slug do Passo 2 |
| `SIGNPATH_SIGNING_POLICY_SLUG` | o Signing policy slug do Passo 2 |

## Passo 5 — Instalar o app do SignPath no GitHub (1 vez só)

O SignPath exige o app oficial para conferir o build:

1. Abra <https://github.com/apps/signpath> e clique em **Install**.
2. Escolha o repositório `persio/monitoramento-cameras`.

---

## Pronto! Como usar

Rode um build:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Ou entre em **Actions → Build Multi-Platform → Run workflow** no GitHub.

O job `build-windows` passa a entregar o arquivo **`MonitoramentoCameras-Windows-Assinado`**.
Baixe esse — é o que não acusa aviso no Windows.

> A assinatura acontece no servidor do SignPath: o `.exe` é enviado, assinado
> e devolvido. Sua chave nunca sai de lá.

---

## Se der erro

| Erro | O que fazer |
|---|---|
| O step de assinatura fica cinza/pulado | Faltou preencher `SIGNPATH_API_TOKEN` ou as variáveis. Confira os nomes. |
| `401 Unauthorized` | Token errado ou revogado. Gere outro no SignPath. |
| `Project not found` | Confira `SIGNPATH_PROJECT_SLUG` e se o projeto existe no SignPath. |
| `Signing policy not found` | Confira `SIGNPATH_SIGNING_POLICY_SLUG`. |
| Pedem revisão manual do repositório | Normal no primeiro uso: o SignPath confere que é open source de verdade. Pode levar alguns dias. |
