// The control panel's data layer.
//
// Every answer here comes from the same functions the MCP tool runs, so the
// page cannot drift from what an agent actually experiences. A UI that
// describes policy from a second source eventually lies.

import { INVALID_URL_REASON, checkTarget, parseAllowlist } from "./guard";
import { SECURITY_HEADERS, fetchHeaderReport, type HeaderReport } from "./headers";

export interface ControlEnv {
  ALLOWED_HOSTS?: string;
  REQUIRE_ACCESS?: string;
}

export interface ConfigPayload {
  server: { name: string; version: string; endpoint: string };
  allowedHosts: string[];
  /** True when every request is denied because no targets are configured. */
  failClosed: boolean;
  access: { enforced: boolean };
  tools: Array<{ name: string; readOnly: boolean }>;
  checkedHeaders: string[];
}

export function configPayload(env: ControlEnv): ConfigPayload {
  const allowedHosts = [...parseAllowlist(env.ALLOWED_HOSTS)].sort();
  return {
    server: { name: "security-headers-mcp", version: "0.1.0", endpoint: "/mcp" },
    allowedHosts,
    failClosed: allowedHosts.length === 0,
    access: { enforced: env.REQUIRE_ACCESS === "true" },
    tools: [{ name: "check_security_headers", readOnly: true }],
    checkedHeaders: [...SECURITY_HEADERS],
  };
}

export type ValidateResult =
  // Shape: the caller sent something that is not a URL at all.
  | { outcome: "invalid"; reason: string }
  // Policy: a real URL this server refuses to fetch.
  | { outcome: "denied"; reason: string }
  | { outcome: "allowed"; report: HeaderReport }
  | { outcome: "error"; reason: string };

export async function validateTarget(
  input: unknown,
  allowlist: ReadonlySet<string>,
  fetchImpl: typeof fetch = fetch,
): Promise<ValidateResult> {
  if (typeof input !== "string" || input.trim() === "") {
    return { outcome: "invalid", reason: "Enter a URL to check." };
  }
  if (input.length > 2048) {
    return { outcome: "invalid", reason: "That URL is too long." };
  }

  const decision = checkTarget(input.trim(), allowlist);
  if (!decision.allowed) {
    // The same split the server uses: shape first, then policy.
    return decision.reason === INVALID_URL_REASON
      ? { outcome: "invalid", reason: "That is not a valid URL." }
      : { outcome: "denied", reason: decision.reason };
  }

  try {
    return { outcome: "allowed", report: await fetchHeaderReport(decision.url, fetchImpl) };
  } catch {
    return { outcome: "error", reason: "The target could not be reached (timeout or network error)." };
  }
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}
