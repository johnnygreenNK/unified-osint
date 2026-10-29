import { describe, expect, it, vi } from "vitest";
import type { SafeFetchResult } from "@unified-osint/core";
import { AdapterHttpError } from "@unified-osint/core";
import { EmailRepAdapter } from "../src/emailrep.js";

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
    finalUrl: "https://emailrep.io/test@example.com",
    ...overrides,
  };
}

describe("EmailRepAdapter", () => {
  it("zwraca znormalizowany rekord reputacji i wysyla naglowki Key/User-Agent", async () => {
    const body = JSON.stringify({
      email: "bill@microsoft.com",
      reputation: "high",
      suspicious: false,
      references: 79,
      details: { credentials_leaked: true, data_breach: true, profiles: ["linkedin"] },
    });
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ body: Buffer.from(body) }));
    const adapter = new EmailRepAdapter({ apiKey: "test-key", userAgent: "UnifiedOSINT-test", fetchFn });

    const records = [];
    for await (const record of adapter.search({ raw: "bill@microsoft.com", type: "email", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }

    expect(records).toHaveLength(1);
    expect(records[0]!.attrs.reputation).toBe("high");
    expect(records[0]!.attrs.credentials_leaked).toBe(true);
    expect(fetchFn).toHaveBeenCalledWith(
      expect.stringContaining("/bill%40microsoft.com"),
      expect.objectContaining({ headers: expect.objectContaining({ Key: "test-key", "User-Agent": "UnifiedOSINT-test" }) })
    );
  });

  it("rzuca AdapterHttpError przy odpowiedzi 401 (nieprawidlowy klucz)", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ status: 401, body: Buffer.from("{}") }));
    const adapter = new EmailRepAdapter({ apiKey: "bad-key", userAgent: "UnifiedOSINT-test", fetchFn });

    const iterator = adapter.search({ raw: "test@example.com", type: "email", hasWildcards: false }, fakeContext());
    await expect(iterator.next()).rejects.toThrow(AdapterHttpError);
  });

  it("rzuca AdapterHttpError przy odpowiedzi 429 (nieautoryzowane API wylaczone / limit)", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ status: 429, body: Buffer.from("{}") }));
    const adapter = new EmailRepAdapter({ apiKey: "", userAgent: "UnifiedOSINT-test", fetchFn });

    const iterator = adapter.search({ raw: "test@example.com", type: "email", hasWildcards: false }, fakeContext());
    await expect(iterator.next()).rejects.toThrow(AdapterHttpError);
  });

  it("odrzuca zapytania innego typu niz email", () => {
    const adapter = new EmailRepAdapter({ apiKey: "test-key", userAgent: "UnifiedOSINT-test" });
    const validation = adapter.validateQuery({ raw: "testuser", type: "username", hasWildcards: false });
    expect(validation.ok).toBe(false);
  });

  it("isConfigured() jest false bez klucza API", () => {
    const adapter = new EmailRepAdapter({ apiKey: "", userAgent: "UnifiedOSINT-test" });
    expect(adapter.isConfigured()).toBe(false);
  });

  it("healthCheck() zwraca not_configured bez wykonywania zadania, gdy brak klucza", async () => {
    const fetchFn = vi.fn();
    const adapter = new EmailRepAdapter({ apiKey: "", userAgent: "UnifiedOSINT-test", fetchFn });

    const result = await adapter.healthCheck();
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.errorCode).toBe("not_configured");
    expect(fetchFn).not.toHaveBeenCalled();
  });
});
