import { describe, expect, it, vi } from "vitest";
import type { SafeFetchResult } from "@unified-osint/core";
import { AdapterHttpError } from "@unified-osint/core";
import { HibpAdapter } from "../src/hibp.js";

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
    finalUrl: "https://haveibeenpwned.com/api/v3/breachedaccount/test",
    ...overrides,
  };
}

describe("HibpAdapter", () => {
  it("zwraca znormalizowane rekordy wyciekow i pastes", async () => {
    const breaches = JSON.stringify([
      {
        Name: "Adobe",
        Title: "Adobe",
        Domain: "adobe.com",
        BreachDate: "2013-10-04",
        PwnCount: 152445165,
        DataClasses: ["Email addresses", "Passwords"],
        IsVerified: true,
      },
    ]);
    const pastes = JSON.stringify([{ Source: "Pastebin", Id: "abc123", Date: "2021-01-01T00:00:00Z", EmailCount: 3 }]);
    const fetchFn = vi
      .fn()
      .mockResolvedValueOnce(fakeResult({ body: Buffer.from(breaches) }))
      .mockResolvedValueOnce(fakeResult({ body: Buffer.from(pastes) }));
    const adapter = new HibpAdapter({
      apiKey: "test-key",
      baseUrl: "https://haveibeenpwned.com/api/v3",
      userAgent: "UnifiedOSINT-test",
      fetchFn,
    });

    const records = [];
    for await (const record of adapter.search({ raw: "test@example.com", type: "email", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }

    expect(records).toHaveLength(2);
    expect(records[0]!.kind).toBe("breach_record");
    expect(records[0]!.attrs.domain).toBe("adobe.com");
    expect(records[1]!.kind).toBe("paste_record");
    expect(records[1]!.attrs.emailCount).toBe(3);

    expect(fetchFn).toHaveBeenCalledWith(
      expect.stringContaining("/breachedaccount/"),
      expect.objectContaining({ headers: expect.objectContaining({ "hibp-api-key": "test-key", "user-agent": "UnifiedOSINT-test" }) })
    );
  });

  it("traktuje 404 jako brak wynikow, nie jako blad", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ status: 404, body: Buffer.from("") }));
    const adapter = new HibpAdapter({ apiKey: "test-key", baseUrl: "https://haveibeenpwned.com/api/v3", userAgent: "UnifiedOSINT-test", fetchFn });

    const records = [];
    for await (const record of adapter.search({ raw: "test@example.com", type: "email", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }
    expect(records).toHaveLength(0);
  });

  it("rzuca AdapterHttpError z retryAfter przy odpowiedzi 429", async () => {
    const fetchFn = vi
      .fn()
      .mockResolvedValue(fakeResult({ status: 429, headers: { "retry-after": "2" }, body: Buffer.from("{}") }));
    const adapter = new HibpAdapter({ apiKey: "test-key", baseUrl: "https://haveibeenpwned.com/api/v3", userAgent: "UnifiedOSINT-test", fetchFn });

    const iterator = adapter.search({ raw: "test@example.com", type: "email", hasWildcards: false }, fakeContext());
    try {
      await iterator.next();
      expect.fail("powinno rzucic");
    } catch (err) {
      expect(err).toBeInstanceOf(AdapterHttpError);
      expect((err as AdapterHttpError).retryAfterHeader).toBe("2");
    }
  });

  it("odrzuca zapytania innego typu niz email", () => {
    const adapter = new HibpAdapter({ apiKey: "test-key", baseUrl: "https://haveibeenpwned.com/api/v3", userAgent: "UnifiedOSINT-test" });
    const validation = adapter.validateQuery({ raw: "testuser", type: "username", hasWildcards: false });
    expect(validation.ok).toBe(false);
  });

  it("isConfigured() jest false bez klucza API", () => {
    const adapter = new HibpAdapter({ apiKey: "", baseUrl: "https://haveibeenpwned.com/api/v3", userAgent: "UnifiedOSINT-test" });
    expect(adapter.isConfigured()).toBe(false);
  });
});
