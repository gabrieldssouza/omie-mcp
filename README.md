# omie-mcp

MCP server para o ERP OMIE, hospedado no Azure Web Apps com login SSO Microsoft para uso
como conector remoto no Claude (claude.ai / Claude Team).

O servidor em si vive em [`omie/`](omie/) — Node/TypeScript, baseado em
[`@codespar/mcp-omie`](https://github.com/codespar/mcp-dev-latam) (30 tools:
clientes, produtos, pedidos, NF, financeiro, estoque etc.), estendido com:

- **`omie/src/oauth.ts`** — authorization server OAuth 2.1 mínimo e stateless
  (state, códigos e tokens selados com AES-256-GCM; PKCE S256; Dynamic Client
  Registration; allowlist de redirect).
- **`omie/src/entra.ts`** — login SSO no Microsoft Entra ID e checagem do grupo.
- **`omie/src/bridge.ts`** — Express: metadata RFC 8414/9728, `/authorize`
  (redireciona para a Microsoft), `/auth/callback`, `/token`, `/register`, e a
  guarda do `/mcp` (só Bearer token — não existe mais chave compartilhada).

## Fluxo de vínculo no Claude

1. Adicione `https://<app>.azurewebsites.net/mcp` como conector.
2. A pessoa clica em **Conectar**; o Claude abre `/authorize`, que manda o
   navegador para a tela de login da Microsoft.
3. Depois do login, `/auth/callback` confere se a conta está no grupo
   **Omie-MCP** e devolve o código para o Claude.
4. O Claude recebe um access token pessoal (1 h). A cada renovação o servidor
   consulta a Microsoft de novo: quem sair do grupo perde o acesso em até 1 h.

O acesso é barrado em dois lugares: no Entra (enterprise app com *Assignment
required* e só o grupo atribuído — quem está fora recebe AADSTS50105 na própria
tela da Microsoft) e no servidor (claim `groups` precisa conter
`AZURE_ALLOWED_GROUP_IDS`, ou o e-mail estar em `AZURE_ALLOWED_EMAILS`).

## Entra ID

App registration **Omie-MCP** (single tenant):

- Redirect URI (Web): `https://<app>.azurewebsites.net/auth/callback`
- Client secret → `AZURE_CLIENT_SECRET`
- Manifest: `"groupMembershipClaims": "ApplicationGroup"` (o token só traz os
  grupos atribuídos ao app, evitando o limite de grupos no token)
- Enterprise app: *Assignment required* = Sim; grupo **Omie-MCP** atribuído

Para dar ou tirar acesso, basta incluir ou remover a pessoa do grupo.

## Azure Web Apps

- **Stack**: Node 22 (Linux)
- **Startup command**: `node dist/index.js` (ou vazio — `npm start` faz o mesmo)
- **App settings**:
  - `OMIE_APP_KEY` / `OMIE_APP_SECRET` — credenciais do OMIE
  - `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` — app registration
  - `AZURE_ALLOWED_GROUP_IDS` — object ID do grupo Omie-MCP
  - `AZURE_ALLOWED_EMAILS` (opcional) — e-mails liberados fora do grupo
  - `MCP_PUBLIC_URL` (opcional) — fixa a URL pública usada no redirect URI
  - `MCP_TOKEN_SECRET` (opcional) — rotaciona todos os tokens emitidos
  - `MCP_ALLOWED_REDIRECT_HOSTS` (opcional) — hosts extras de callback OAuth
- **Deploy**: GitHub Actions ([workflow](.github/workflows/master_omie-mcp.yml)),
  publish profile no secret `AZURE_WEBAPP_PUBLISH_PROFILE`. O artefato publicado é
  o conteúdo de `omie/`.

O modo HTTP liga automaticamente quando `PORT` está definido (o App Service
injeta). Sem `PORT`, o servidor roda em stdio — uso local via Claude Desktop
continua funcionando como descrito em [`omie/README.md`](omie/README.md).

## Desenvolvimento local

```bash
cd omie
npm install
npm run build
cp ../.env.example .env  # preencha, e adicione http://localhost:3000/auth/callback no app registration
node --env-file=.env dist/index.js   # PORT=3000 no .env
# conecte http://localhost:3000/mcp no MCP Inspector
```
