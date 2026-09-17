import { describe, expect, it, vi } from "vitest";
import { fetchHeaderReport, gradeHeaders } from "../src/headers";

describe("gradeHeaders", () => {
  it("splits security headers into present and missing", () => {
    const result = gradeHeaders(
      new Headers({
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
      }),
    );
    expect(result.present).toEqual(["strict-transport-security", "x-content-type-options"]);
    expect(result.missing).toEqual([
      "content-security-policy",
      "x-frame-options",
      "referrer-policy",
      "permissions-policy",
    ]);
  });
});

describe("fetchHeaderReport", () => {
  it("never follows redirects and reports the Location instead", async () => {
    const fakeFetch = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(null, {
          status: 301,
          headers: { Location: "https://somewhere-else.net/" },
        }),
    );

    const report = await fetchHeaderReport(
      new URL("https://example.com/"),
      fakeFetch as unknown as typeof fetch,
    );

    expect(fakeFetch).toHaveBeenCalledOnce();
    expect(fakeFetch.mock.calls[0]?.[1]?.redirect).toBe("manual");
    expect(report.status).toBe(301);
    expect(report.redirectTo).toBe("https://somewhere-else.net/");
  });

  it("propagates network failures so the tool can return an error result", async () => {
    const failingFetch = vi.fn(async () => {
      throw new TypeError("network down");
    });
    await expect(
      fetchHeaderReport(new URL("https://example.com/"), failingFetch as unknown as typeof fetch),
    ).rejects.toThrow("network down");
  });
});
