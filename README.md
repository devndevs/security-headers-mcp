# security-headers-mcp

A small remote MCP server on Cloudflare Workers. One read-only tool,
`check_security_headers`, fetches an allowlisted HTTPS URL once and reports
which common security headers are present or missing.

## Security decisions

- **Deny by default.** Only hostnames in `ALLOWED_HOSTS` (wrangler.jsonc) can be
  fetched. An empty list denies everything.
- **Two validation layers.** A zod schema checks shape (a valid URL, bounded
  length). `checkTarget()` enforces policy: https only, default port, no
  credentials, exact hostname match.
- **No redirects followed.** An allowlisted host could bounce the request
  off-list, so redirects are reported in `redirectTo`, never followed.
- **Generic denial messages.** Callers can't enumerate the allowlist.
- **Logs record hostnames only.** Query strings can carry tokens.
- **Annotations are hints.** `readOnlyHint` tells clients what to expect; the
  server enforces it.

## Run it

```sh
npm install
npm run check   # types + tests + deploy dry run
npm run dev     # http://localhost:8787/mcp
npm run deploy  # https://security-headers-mcp.<your-subdomain>.workers.dev/mcp
```

Test with the MCP Inspector (connect to `http://localhost:8787/mcp`):

```sh
npx @modelcontextprotocol/inspector@latest
```

## Demo checks

The default allowlist is `example.com,cloudflare.com`.

| Input | Expected |
| --- | --- |
| `https://example.com/` | status 200, all six headers missing |
| `https://cloudflare.com/` | status 301, `redirectTo` www.cloudflare.com, not followed |
| `https://www.cloudflare.com/` | denied: host is not on the allowlist |
| `not a url` | input validation error from the schema layer |

Add your own domain to `ALLOWED_HOSTS`, then run `npm run typecheck` to refresh types.

## Layout

- `src/index.ts` registers the tool and serves MCP via `createMcpHandler`
- `src/guard.ts` holds the allowlist policy (pure, unit-tested)
- `src/headers.ts` does the single fetch and grades the headers
- `test/` covers every denial rule and the no-redirect behavior
