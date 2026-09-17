import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";
import { checkTarget, hostForLog, parseAllowlist } from "./guard";
import { fetchHeaderReport } from "./headers";

const TOOL = "check_security_headers";

/** One structured JSON line per tool call. Workers Logs turns the fields into filters. */
function logCall(fields: Record<string, unknown>): void {
  console.log(JSON.stringify({ event: "tool_call", tool: TOOL, ...fields }));
}

function createServer(env: Env): McpServer {
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
        redirectTo: z.string().nullable(),
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
        logCall({ decision: "deny", host: hostForLog(url), reason: decision.reason });
        return {
          isError: true,
          content: [{ type: "text", text: `Denied: ${decision.reason}.` }],
        };
      }

      const host = decision.url.hostname;
      try {
        const report = await fetchHeaderReport(decision.url);
        logCall({
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
  fetch(request, env, ctx) {
    // A fresh server per request, with this request's env in scope.
    return createMcpHandler(() => createServer(env))(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
