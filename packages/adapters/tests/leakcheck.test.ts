import { describe, expect, it, vi } from "vitest";
import type { SafeFetchResult } from "@unified-osint/core";
import { AdapterHttpError } from "@unified-osint/core";
import { LeakCheckAdapter } from "../src/leakcheck.js";

function fakeContext() {
  return {
    searchId: "s1",
    userId: "u1",
    userRole: "analyst" as const,
    correlationId: "c1",
    signal: new AbortController().signal,
    timeoutMs: 5000,
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
}

function fakeResult(overrides: Partial<SafeFetchResult>): SafeFetchResult {
  return {
    status: 200,
    headers: {},
    body: Buffer.from(""),
    finalUrl: "https://leakcheck.io/api/v2/query/test",
    ...overrides,
  };
}

describe("LeakCheckAdapter", () => {
  it("zwraca znormalizowane rekordy przy sukcesie, pola wrazliwe jawne (decyzja uzytkownika: bez maskowania)", async () => {
    const body = JSON.stringify({
      success: true,
      found: 1,
      quota: 399,
      result: [
        {
          email: "test@example.com",
          username: "testuser",
          password: "plaintext-pass",
          source: { name: "BreachedWebsite.net", breach_date: "2019-07" },
          fields: ["username", "password"],
        },
      ],
    });
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ body: Buffer.from(body) }));
    const adapter = new LeakCheckAdapter({ apiKey: "test-key", baseUrl: "https://leakcheck.io/api/v2", fetchFn });

    const records = [];
    for await (const record of adapter.search({ raw: "test@example.com", type: "email", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }

    expect(records).toHaveLength(1);
    const record = records[0]!;
    expect(record.attrs.email).toBe("test@example.com");
    expect(record.attrs.password).toBe("plaintext-pass");
    expect(record.attrs.source).toBe("BreachedWebsite.net");

    expect(fetchFn).toHaveBeenCalledWith(
      expect.stringContaining("/query/test%40example.com?type=email"),
      expect.objectContaining({ headers: expect.objectContaining({ "X-API-Key": "test-key" }) })
    );
  });

  it("zwraca pusta liste, gdy success=true i found=0", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ body: Buffer.from(JSON.stringify({ success: true, found: 0, quota: 400, result: [] })) }));
    const adapter = new LeakCheckAdapter({ apiKey: "test-key", baseUrl: "https://leakcheck.io/api/v2", fetchFn });

    const records = [];
    for await (const record of adapter.search({ raw: "test@example.com", type: "email", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }
    expect(records).toHaveLength(0);
  });

  it("rzuca AdapterHttpError przy odpowiedzi 401", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ status: 401, body: Buffer.from("{}") }));
    const adapter = new LeakCheckAdapter({ apiKey: "bad-key", baseUrl: "https://leakcheck.io/api/v2", fetchFn });

    const iterator = adapter.search({ raw: "test@example.com", type: "email", hasWildcards: false }, fakeContext());
    await expect(iterator.next()).rejects.toThrow(AdapterHttpError);
  });

  it("odrzuca zapytania z wildcardami", () => {
    const adapter = new LeakCheckAdapter({ apiKey: "test-key", baseUrl: "https://leakcheck.io/api/v2" });
    const validation = adapter.validateQuery({ raw: "tes*", type: "email", hasWildcards: true });
    expect(validation.ok).toBe(false);
  });

  it("odrzuca zapytania krotsze niz 3 znaki", () => {
    const adapter = new LeakCheckAdapter({ apiKey: "test-key", baseUrl: "https://leakcheck.io/api/v2" });
    const validation = adapter.validateQuery({ raw: "ab", type: "username", hasWildcards: false });
    expect(validation.ok).toBe(false);
  });

  it("isConfigured() jest false bez klucza API", () => {
    const adapter = new LeakCheckAdapter({ apiKey: "", baseUrl: "https://leakcheck.io/api/v2" });
    expect(adapter.isConfigured()).toBe(false);
  });
});
