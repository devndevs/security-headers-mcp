import { describe, expect, it, vi } from "vitest";
import { configPayload, validateTarget } from "../src/api";
import { parseAllowlist } from "../src/guard";

const allow = parseAllowlist("example.com");

describe("configPayload", () => {
  it("reports the live allowlist, sorted", () => {
    const config = configPayload({ ALLOWED_HOSTS: "b.com,a.com" });
    expect(config.allowedHosts).toEqual(["a.com", "b.com"]);
    expect(config.failClosed).toBe(false);
  });

  it("flags the fail-closed state so the panel can warn about it", () => {
    const config = configPayload({});
    expect(config.allowedHosts).toEqual([]);
    expect(config.failClosed).toBe(true);
  });

  it("reports whether Access enforcement is on", () => {
    expect(configPayload({ REQUIRE_ACCESS: "true" }).access.enforced).toBe(true);
    expect(configPayload({ REQUIRE_ACCESS: "false" }).access.enforced).toBe(false);
  });
});

describe("validateTarget: shape problems belong on the field", () => {
  it.each([
    [undefined, "Enter a URL to check."],
    ["", "Enter a URL to check."],
    ["   ", "Enter a URL to check."],
    ["not a url", "That is not a valid URL."],
    [`https://example.com/${"a".repeat(2100)}`, "That URL is too long."],
  ])("treats %s as invalid input", async (input, reason) => {
    await expect(validateTarget(input, allow)).resolves.toEqual({ outcome: "invalid", reason });
  });
});

describe("validateTarget: policy denials are an answer, not a typo", () => {
  it.each([
    ["http://example.com/", "only https URLs are allowed"],
    ["https://evil.example.net/", "host is not on the allowlist"],
    ["https://example.com:8443/", "non-default ports are not allowed"],
    ["https://user:pass@example.com/", "URLs with credentials are not allowed"],
  ])("denies %s", async (input, reason) => {
    await expect(validateTarget(input, allow)).resolves.toEqual({ outcome: "denied", reason });
  });

  it("uses the same policy the tool uses, so the panel cannot drift", async () => {
    const empty = parseAllowlist("");
    await expect(validateTarget("https://example.com/", empty)).resolves.toEqual({
      outcome: "denied",
      reason: "no targets are configured",
    });
  });
});

describe("validateTarget: allowed", () => {
  it("returns the header report", async () => {
    const fakeFetch = vi.fn(async () =>
      new Response(null, { status: 200, headers: { "X-Content-Type-Options": "nosniff" } }),
    );
    const result = await validateTarget("https://example.com/", allow, fakeFetch as unknown as typeof fetch);
    expect(result.outcome).toBe("allowed");
    if (result.outcome === "allowed") {
      expect(result.report.status).toBe(200);
      expect(result.report.present).toEqual(["x-content-type-options"]);
    }
  });

  it("reports an unreachable target without throwing", async () => {
    const failing = vi.fn(async () => { throw new TypeError("network down"); });
    await expect(
      validateTarget("https://example.com/", allow, failing as unknown as typeof fetch),
    ).resolves.toEqual({
      outcome: "error",
      reason: "The target could not be reached (timeout or network error).",
    });
  });
});
