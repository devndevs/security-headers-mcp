import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { readAccessConfig, verifyAccessJwt } from "../src/access";

const TEAM = "https://example-team.cloudflareaccess.com";
const AUD = "aaaabbbbccccddddeeeeffff00001111";
const config = { teamDomain: TEAM, policyAud: AUD };

let signingKey: CryptoKey;
let publicKey: CryptoKey;
let otherKey: CryptoKey;

beforeAll(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true });
  signingKey = pair.privateKey as CryptoKey;
  publicKey = pair.publicKey as CryptoKey;
  const impostor = await generateKeyPair("RS256", { extractable: true });
  otherKey = impostor.privateKey as CryptoKey;
  await exportJWK(publicKey);
});

async function token(claims: Record<string, unknown>, opts: {
  issuer?: string;
  audience?: string;
  expires?: string;
  key?: CryptoKey;
} = {}) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256" })
    .setIssuedAt()
    .setIssuer(opts.issuer ?? TEAM)
    .setAudience(opts.audience ?? AUD)
    .setExpirationTime(opts.expires ?? "5m")
    .sign(opts.key ?? signingKey);
}

function request(jwt?: string) {
  return new Request("https://worker.example/mcp", {
    method: "POST",
    headers: jwt ? { "cf-access-jwt-assertion": jwt } : {},
  });
}

describe("readAccessConfig", () => {
  it("returns null when either value is missing", () => {
    expect(readAccessConfig({ TEAM_DOMAIN: TEAM })).toBeNull();
    expect(readAccessConfig({ POLICY_AUD: AUD })).toBeNull();
    expect(readAccessConfig({})).toBeNull();
  });

  it("trims a trailing slash so the issuer comparison matches", () => {
    expect(readAccessConfig({ TEAM_DOMAIN: `${TEAM}/`, POLICY_AUD: AUD })).toEqual(config);
  });
});

describe("verifyAccessJwt: accepted", () => {
  it("accepts a correctly signed assertion and returns the user", async () => {
    const jwt = await token({ email: "deven@example.com" });
    await expect(verifyAccessJwt(request(jwt), config, publicKey)).resolves.toEqual({
      ok: true,
      identity: "deven@example.com",
    });
  });

  it("identifies a service token by its common name, not as a person", async () => {
    const jwt = await token({ common_name: "ci-smoke-test", sub: "" });
    await expect(verifyAccessJwt(request(jwt), config, publicKey)).resolves.toEqual({
      ok: true,
      identity: "service:ci-smoke-test",
    });
  });
});

describe("verifyAccessJwt: rejected", () => {
  it("denies when enforcement is on but config is incomplete", async () => {
    const jwt = await token({ email: "deven@example.com" });
    const decision = await verifyAccessJwt(request(jwt), null, publicKey);
    expect(decision).toEqual({ ok: false, reason: "access is enforced but not configured" });
  });

  it("denies a request with no assertion header", async () => {
    const decision = await verifyAccessJwt(request(), config, publicKey);
    expect(decision).toEqual({ ok: false, reason: "missing Access assertion" });
  });

  it("denies a token signed by a different key", async () => {
    const jwt = await token({ email: "deven@example.com" }, { key: otherKey });
    const decision = await verifyAccessJwt(request(jwt), config, publicKey);
    expect(decision.ok).toBe(false);
  });

  it("denies a token minted for another application", async () => {
    const jwt = await token({ email: "deven@example.com" }, { audience: "some-other-app" });
    const decision = await verifyAccessJwt(request(jwt), config, publicKey);
    expect(decision.ok).toBe(false);
  });

  it("denies a token from another team domain", async () => {
    const jwt = await token({ email: "deven@example.com" }, {
      issuer: "https://attacker.cloudflareaccess.com",
    });
    const decision = await verifyAccessJwt(request(jwt), config, publicKey);
    expect(decision.ok).toBe(false);
  });

  it("denies an expired token", async () => {
    const jwt = await token({ email: "deven@example.com" }, { expires: "-1m" });
    const decision = await verifyAccessJwt(request(jwt), config, publicKey);
    expect(decision.ok).toBe(false);
  });

  it("denies an unsigned token", async () => {
    const jwt = await token({ email: "deven@example.com" });
    const [header, payload] = jwt.split(".");
    const unsigned = `${header}.${payload}.`;
    const decision = await verifyAccessJwt(request(unsigned), config, publicKey);
    expect(decision.ok).toBe(false);
  });
});
