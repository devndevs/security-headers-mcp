// Fetch layer: one GET, no redirects, headers only.

export const SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
] as const;

export interface HeaderReport {
  url: string;
  status: number;
  /** Location header when the target redirects. Reported, never followed. */
  redirectTo: string | null;
  present: string[];
  missing: string[];
}

export function gradeHeaders(headers: Headers): { present: string[]; missing: string[] } {
  const present: string[] = [];
  const missing: string[] = [];
  for (const name of SECURITY_HEADERS) {
    (headers.has(name) ? present : missing).push(name);
  }
  return { present, missing };
}

export async function fetchHeaderReport(
  url: URL,
  fetchImpl: typeof fetch = fetch,
  timeoutMs = 5000,
): Promise<HeaderReport> {
  const response = await fetchImpl(url.toString(), {
    method: "GET",
    // Following redirects would let an allowlisted host bounce this request off-list.
    redirect: "manual",
    signal: AbortSignal.timeout(timeoutMs),
    headers: { "user-agent": "security-headers-mcp/0.1" },
  });

  // Only headers matter. Don't download the body.
  await response.body?.cancel();

  return {
    url: url.toString(),
    status: response.status,
    redirectTo: response.headers.get("location"),
    ...gradeHeaders(response.headers),
  };
}
