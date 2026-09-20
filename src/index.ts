import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";
import { readAccessConfig, verifyAccessJwt, type AccessEnv } from "./access";
import { configPayload, json, validateTarget } from "./api";
import { checkTarget, hostForLog, parseAllowlist } from "./guard";
import { fetchHeaderReport } from "./headers";
import { controlPanelHtml } from "./ui";

const TOOL = "check_security_headers";

/** One structured JSON line per tool call. Workers Logs turns the fields into filters. */
function logCall(fields: Record<string, unknown>): void {
  console.log(JSON.stringify({ event: "tool_call", tool: TOOL, ...fields }));
}

function createServer(env: Env, caller?: string): McpServer {
  const allowlist = parseAllowlist(env.ALLOWED_HOSTS);

  const server = new McpServer({
    name: "security-headers-mcp",
    version: "0.1.0",
  });

  server.registerTool(
    TOOL,
    {
      title: "Check security headers",
      description:
        "Fetches an allowlisted https URL once and reports which common security " +
        "headers are present or missing. Read-only. Redirects are reported, never followed.",
      // Shape check. Policy (scheme, host, port) is enforced in checkTarget().
      inputSchema: z.object({
        url: z.url().max(2048).describe("An https:// URL on an allowlisted host"),
      }),
      outputSchema: z.object({
        url: z.string(),
        status: z.number().int(),
        // anyOf branches, not type: ["string","null"]: some MCP clients read
        // `type` as a single string and drop or reject the constraint.
        redirectTo: z.union([z.string(), z.literal(null)]),
        present: z.array(z.string()),
        missing: z.array(z.string()),
      }),
      // Hints for clients, not enforcement. The server enforces.
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ url }) => {
      const started = Date.now();
      const decision = checkTarget(url, allowlist);

      if (!decision.allowed) {
        logCall({ caller, decision: "deny", host: hostForLog(url), reason: decision.reason });
        return {
          isError: true,
          content: [{ type: "text", text: `Denied: ${decision.reason}.` }],
        };
      }

      const host = decision.url.hostname;
      try {
        const report = await fetchHeaderReport(decision.url);
        logCall({
          caller,
          decision: "allow",
          host,
          status: report.status,
          missing: report.missing.length,
          ms: Date.now() - started,
        });
        return {
          content: [{ type: "text", text: JSON.stringify(report, null, 2) }],
          structuredContent: { ...report },
        };
      } catch (error) {
        logCall({
          caller,
          decision: "allow",
          host,
          outcome: "fetch_failed",
          error: error instanceof Error ? error.name : "UnknownError",
          ms: Date.now() - started,
        });
        return {
          isError: true,
          content: [{ type: "text", text: "The target could not be reached (timeout or network error)." }],
        };
      }
    },
  );

  return server;
}

export default {
  async fetch(request, env, ctx) {
    // Enforcement is an explicit deployment decision. Once it is on, missing
    // configuration denies every request instead of quietly serving them.
    let caller: string | undefined;
    if (env.REQUIRE_ACCESS === "true") {
      const decision = await verifyAccessJwt(request, readAccessConfig(env as AccessEnv));
      if (!decision.ok) {
        console.log(JSON.stringify({ event: "access_denied", reason: decision.reason }));
        return new Response("Forbidden", { status: 403 });
      }
      caller = decision.identity;
    }

    // The control panel rides on the same Worker and the same policy code.
    // Anything that is not a panel route falls through to MCP untouched.
    const { pathname } = new URL(request.url);

    if (pathname === "/" && request.method === "GET") {
      return new Response(controlPanelHtml, {
        headers: {
          "content-type": "text/html; charset=utf-8",
          // The page has no third-party anything, so say so.
          "content-security-policy":
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'",
          "referrer-policy": "no-referrer",
          "x-content-type-options": "nosniff",
        },
      });
    }

    if (pathname === "/api/config") {
      if (request.method !== "GET") return json({ error: "method not allowed" }, 405);
      return json(configPayload(env));
    }

    if (pathname === "/api/validate") {
      if (request.method !== "POST") return json({ error: "method not allowed" }, 405);
      let body: unknown;
      try {
        body = await request.json();
      } catch {
        return json({ outcome: "invalid", reason: "Send a JSON body with a url field." }, 400);
      }
      const url = (body as { url?: unknown } | null)?.url;
      const result = await validateTarget(url, parseAllowlist(env.ALLOWED_HOSTS));
      logCall({
        caller,
        source: "control-panel",
        decision: result.outcome === "allowed" ? "allow" : "deny",
        host: typeof url === "string" ? hostForLog(url) : null,
        reason: result.outcome === "allowed" ? undefined : result.reason,
      });
      return json(result);
    }

    // A fresh server per request, with this request's env and caller in scope.
    return createMcpHandler(() => createServer(env, caller))(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
