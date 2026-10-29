import { describe, expect, it, vi } from "vitest";
import type { SafeFetchResult } from "@unified-osint/core";
import { AdapterHttpError } from "@unified-osint/core";
import { SnusbaseAdapter } from "../src/snusbase.js";

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
    finalUrl: "https://api.snusbase.com/data/search",
    ...overrides,
  };
}

describe("SnusbaseAdapter", () => {
  it("maskuje pola wrazliwe i zwraca znormalizowane rekordy przy sukcesie", async () => {
    const body = JSON.stringify({
      took: 1,
      size: 1,
      results: {
        "breach-2021": [
          { email: "test@example.com", username: "testuser", hash: "ab12cd34ef", password: "plaintext", uid: 42 },
        ],
      },
    });
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ body: Buffer.from(body) }));
    const adapter = new SnusbaseAdapter({ apiKey: "test-key", baseUrl: "https://api.snusbase.com", fetchFn });

    const records = [];
    for await (const record of adapter.search({ raw: "test@example.com", type: "email", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }

    expect(records).toHaveLength(1);
    const record = records[0]!;
    expect(record.attrs.email).toBe("test@example.com");
    expect(record.attrs.hashMasked).toBe(true);
    expect(record.attrs.hashPrefix).toBe("ab12…");
    expect(record.attrs.hash).toBeUndefined();
    expect(record.attrs.passwordMasked).toBe(true);
    expect(record.attrs.password).toBeUndefined();
    expect(record.sourceRecordId).toBe("42");

    expect(fetchFn).toHaveBeenCalledWith(
      "https://api.snusbase.com/data/search",
      expect.objectContaining({ headers: expect.objectContaining({ Auth: "test-key" }) })
    );
  });

  it("rzuca AdapterHttpError przy odpowiedzi 401", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ status: 401, body: Buffer.from("{}") }));
    const adapter = new SnusbaseAdapter({ apiKey: "bad-key", baseUrl: "https://api.snusbase.com", fetchFn });

    const iterator = adapter.search({ raw: "test@example.com", type: "email", hasWildcards: false }, fakeContext());
    await expect(iterator.next()).rejects.toThrow(AdapterHttpError);
  });

  it("rzuca AdapterHttpError z retryAfter przy odpowiedzi 429", async () => {
    const fetchFn = vi
      .fn()
      .mockResolvedValue(fakeResult({ status: 429, headers: { "retry-after": "5" }, body: Buffer.from("{}") }));
    const adapter = new SnusbaseAdapter({ apiKey: "test-key", baseUrl: "https://api.snusbase.com", fetchFn });

    const iterator = adapter.search({ raw: "test@example.com", type: "email", hasWildcards: false }, fakeContext());
    try {
      await iterator.next();
      expect.fail("powinno rzucic");
    } catch (err) {
      expect(err).toBeInstanceOf(AdapterHttpError);
      expect((err as AdapterHttpError).retryAfterHeader).toBe("5");
    }
  });

  it("nie wywraca generatora, gdy JSON jest uszkodzony - rzuca jasny blad", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ body: Buffer.from("nie-jest-json") }));
    const adapter = new SnusbaseAdapter({ apiKey: "test-key", baseUrl: "https://api.snusbase.com", fetchFn });

    const iterator = adapter.search({ raw: "test@example.com", type: "email", hasWildcards: false }, fakeContext());
    await expect(iterator.next()).rejects.toThrow(/JSON/);
  });

  it("odrzuca zapytania z wildcardami", () => {
    const adapter = new SnusbaseAdapter({ apiKey: "test-key", baseUrl: "https://api.snusbase.com" });
    const validation = adapter.validateQuery({ raw: "test*", type: "email", hasWildcards: true });
    expect(validation.ok).toBe(false);
  });

  it("isConfigured() jest false bez klucza API", () => {
    const adapter = new SnusbaseAdapter({ apiKey: "", baseUrl: "https://api.snusbase.com" });
    expect(adapter.isConfigured()).toBe(false);
  });
});
