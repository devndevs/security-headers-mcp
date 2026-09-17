import { describe, expect, it } from "vitest";
import { checkTarget, hostForLog, parseAllowlist } from "../src/guard";

const allow = parseAllowlist("example.com, Docs.Example.org ");

describe("parseAllowlist", () => {
  it("trims, lowercases, and drops empty entries", () => {
    expect([...parseAllowlist(" A.com, ,b.com,")]).toEqual(["a.com", "b.com"]);
  });

  it("returns an empty set when the variable is missing", () => {
    expect(parseAllowlist(undefined).size).toBe(0);
  });
});

describe("checkTarget: allowed", () => {
  it("allows an https URL on an allowlisted host", () => {
    expect(checkTarget("https://example.com/", allow).allowed).toBe(true);
  });

  it("matches hostnames case-insensitively", () => {
    expect(checkTarget("https://DOCS.example.ORG/path?q=1", allow).allowed).toBe(true);
  });

  it("treats an explicit :443 as the default port", () => {
    expect(checkTarget("https://example.com:443/", allow).allowed).toBe(true);
  });
});

describe("checkTarget: denied (the release gate)", () => {
  const denied: Array<[string, string]> = [
    ["http://example.com/", "only https URLs are allowed"],
    ["https://evil.example.net/", "host is not on the allowlist"],
    ["https://sub.example.com/", "host is not on the allowlist"],
    ["https://example.com.evil.net/", "host is not on the allowlist"],
    ["https://example.com@evil.net/", "URLs with credentials are not allowed"],
    ["https://user:pass@example.com/", "URLs with credentials are not allowed"],
    ["https://example.com:8443/", "non-default ports are not allowed"],
    ["https://93.184.215.14/", "host is not on the allowlist"],
    ["file:///etc/passwd", "only https URLs are allowed"],
    ["not a url", "not a valid URL"],
  ];

  it.each(denied)("denies %s", (input, reason) => {
    expect(checkTarget(input, allow)).toEqual({ allowed: false, reason });
  });

  it("fails closed when no hosts are configured", () => {
    expect(checkTarget("https://example.com/", parseAllowlist(""))).toEqual({
      allowed: false,
      reason: "no targets are configured",
    });
  });
});

describe("hostForLog", () => {
  it("keeps the hostname and drops the path and query", () => {
    expect(hostForLog("https://example.com/reset?token=secret")).toBe("example.com");
  });

  it("returns null for unparseable input", () => {
    expect(hostForLog("not a url")).toBeNull();
  });
});
