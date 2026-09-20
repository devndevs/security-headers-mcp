// Policy layer: decides whether a target may be fetched at all.
// Pure functions with no I/O, so every rule is unit-testable.

/** Shared so the API can tell a malformed URL apart from a policy denial. */
export const INVALID_URL_REASON = "not a valid URL";

export type TargetDecision =
  | { allowed: true; url: URL }
  | { allowed: false; reason: string };

/** Parse a comma-separated hostname list. Empty or missing denies everything. */
export function parseAllowlist(raw: string | undefined): ReadonlySet<string> {
  return new Set(
    (raw ?? "")
      .split(",")
      .map((host) => host.trim().toLowerCase())
      .filter((host) => host.length > 0),
  );
}

/**
 * Deny by default. A target passes only if it is https, uses the default port,
 * carries no credentials, and its hostname exactly matches an allowlist entry.
 * Reasons stay generic so a caller can't enumerate what is allowed.
 */
export function checkTarget(
  input: string,
  allowlist: ReadonlySet<string>,
): TargetDecision {
  if (allowlist.size === 0) {
    return { allowed: false, reason: "no targets are configured" };
  }

  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return { allowed: false, reason: INVALID_URL_REASON };
  }

  if (url.protocol !== "https:") {
    return { allowed: false, reason: "only https URLs are allowed" };
  }
  if (url.username !== "" || url.password !== "") {
    return { allowed: false, reason: "URLs with credentials are not allowed" };
  }
  if (url.port !== "") {
    return { allowed: false, reason: "non-default ports are not allowed" };
  }
  if (!allowlist.has(url.hostname)) {
    return { allowed: false, reason: "host is not on the allowlist" };
  }

  return { allowed: true, url };
}

/** Hostname for logging only. Never log full URLs: query strings can carry tokens. */
export function hostForLog(input: string): string | null {
  try {
    return new URL(input).hostname;
  } catch {
    return null;
  }
}
