// Identity layer: verifies the JWT Cloudflare Access puts on every request it
// forwards. Access proves who the caller is; this file decides whether to
// believe the header, which is the part that is easy to get wrong.

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

export interface AccessConfig {
  /** https://<team-name>.cloudflareaccess.com */
  teamDomain: string;
  /** The Application Audience (AUD) tag of the Access application. */
  policyAud: string;
}

export type AccessDecision =
  | { ok: true; identity: string }
  | { ok: false; reason: string };

export interface AccessEnv {
  REQUIRE_ACCESS?: string;
  TEAM_DOMAIN?: string;
  POLICY_AUD?: string;
}

/** Returns null when enforcement is on but the configuration is incomplete. */
export function readAccessConfig(env: AccessEnv): AccessConfig | null {
  const teamDomain = (env.TEAM_DOMAIN ?? "").trim().replace(/\/$/, "");
  const policyAud = (env.POLICY_AUD ?? "").trim();
  if (teamDomain === "" || policyAud === "") return null;
  return { teamDomain, policyAud };
}

// Access rotates its signing key roughly every six weeks, so the key set is
// fetched and cached rather than pinned in config.
const keySets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function keySetFor(teamDomain: string) {
  let keys = keySets.get(teamDomain);
  if (!keys) {
    keys = createRemoteJWKSet(new URL(`${teamDomain}/cdn-cgi/access/certs`));
    keySets.set(teamDomain, keys);
  }
  return keys;
}

/** Service tokens authenticate as a machine, so there is no email claim. */
function identityFrom(payload: JWTPayload): string {
  const email = typeof payload.email === "string" ? payload.email : "";
  const commonName = typeof payload.common_name === "string" ? payload.common_name : "";
  return email || (commonName ? `service:${commonName}` : "") || payload.sub || "unknown";
}

export async function verifyAccessJwt(
  request: Request,
  config: AccessConfig | null,
  getKey: Parameters<typeof jwtVerify>[1] | null = null,
): Promise<AccessDecision> {
  // Enforcement without configuration denies everything. Never fall open.
  if (config === null) {
    return { ok: false, reason: "access is enforced but not configured" };
  }

  // The header is the one to trust. The CF_Authorization cookie is not
  // guaranteed to be sent, and a cookie is the wrong thing to authorize on.
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) {
    return { ok: false, reason: "missing Access assertion" };
  }

  try {
    const { payload } = await jwtVerify(token, getKey ?? keySetFor(config.teamDomain), {
      issuer: config.teamDomain,
      audience: config.policyAud,
      // Pinned so a token cannot pick its own algorithm.
      algorithms: ["RS256"],
    });
    return { ok: true, identity: identityFrom(payload) };
  } catch (error) {
    // The reason stays generic to the caller; the detail goes to the log.
    return {
      ok: false,
      reason: error instanceof Error ? error.message : "assertion failed verification",
    };
  }
}
