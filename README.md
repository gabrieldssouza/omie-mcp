# omie-mcp

MCP server para o ERP OMIE, hospedado no Azure Web Apps com bridge OAuth para uso
como conector remoto no Claude (claude.ai / Claude Team).

O servidor em si vive em [`omie/`](omie/) — Node/TypeScript, baseado em
[`@codespar/mcp-omie`](https://github.com/codespar/mcp-dev-latam) (30 tools:
clientes, produtos, pedidos, NF, financeiro, estoque etc.), estendido com:

- **`omie/src/oauth.ts`** — authorization server OAuth 2.1 mínimo e stateless
  (códigos e tokens assinados por HMAC derivado da `MCP_BRIDGE_KEY`; PKCE S256;
  Dynamic Client Registration; allowlist de redirect).
- **`omie/src/bridge.ts`** — Express: metadata RFC 8414/9728, `/authorize`
  (tela de chave), `/token`, `/register`, e a guarda do `/mcp`
  (Bearer token, `?key=` ou header `X-Bridge-Key`).

## Fluxo de vínculo no Claude

1. Adicione `https://<app>.azurewebsites.net/mcp` como conector (sem key na URL).
2. O Claude descobre os endpoints OAuth e abre o navegador em `/authorize`.
3. A pessoa digita a chave (`MCP_BRIDGE_KEY`) e clica em **Vincular**.
4. O Claude recebe um access token pessoal (1 h, renovado por refresh token
   por até 90 dias de janela deslizante).

Trocar a `MCP_BRIDGE_KEY` (ou `MCP_TOKEN_SECRET`) revoga todos os tokens.

## Azure Web Apps

- **Stack**: Node 22 (Linux)
- **Startup command**: `node dist/index.js` (ou vazio — `npm start` faz o mesmo)
- **App settings**:
  - `OMIE_APP_KEY` / `OMIE_APP_SECRET` — credenciais do OMIE
  - `MCP_BRIDGE_KEY` — chave do vínculo (padrão: `omie-mcp-bridge-2026`)
  - `SCM_DO_BUILD_DURING_DEPLOYMENT=true` — Oryx roda `npm install` + `npm run build`
  - `MCP_ALLOWED_REDIRECT_HOSTS` (opcional) — hosts extras de callback OAuth
  - `MCP_TOKEN_SECRET` (opcional) — rotaciona tokens sem trocar a chave
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
OMIE_APP_KEY=... OMIE_APP_SECRET=... PORT=3000 node dist/index.js
# http://localhost:3000/mcp?key=omie-mcp-bridge-2026
```
