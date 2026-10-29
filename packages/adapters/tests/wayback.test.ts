import { describe, expect, it, vi } from "vitest";
import type { SafeFetchResult } from "@unified-osint/core";
import { AdapterHttpError } from "@unified-osint/core";
import { WaybackAdapter } from "../src/wayback.js";

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
    finalUrl: "http://web.archive.org/cdx/search/cdx",
    ...overrides,
  };
}

describe("WaybackAdapter", () => {
  it("parsuje wiersz naglowka dynamicznie, niezaleznie od kolejnosci pol", async () => {
    const body = JSON.stringify([
      ["original", "timestamp", "statuscode", "digest", "mimetype", "length"],
      ["https://example.com/", "20200101000000", "200", "ABC123", "text/html", "1024"],
    ]);
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ body: Buffer.from(body) }));
    const adapter = new WaybackAdapter({ enabled: true, fetchFn });

    const records = [];
    for await (const record of adapter.search({ raw: "example.com", type: "domain", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }

    expect(records).toHaveLength(1);
    expect(records[0]!.attrs.originalUrl).toBe("https://example.com/");
    expect(records[0]!.canonicalUrl).toBe("https://web.archive.org/web/20200101000000/https://example.com/");
    expect(records[0]!.observedAt).toBe("2020-01-01T00:00:00.000Z");
  });

  it("uzywa matchType=domain dla zapytan typu domain", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ body: Buffer.from("") }));
    const adapter = new WaybackAdapter({ enabled: true, fetchFn });

    const iterator = adapter.search({ raw: "example.com", type: "domain", hasWildcards: false }, fakeContext());
    await iterator.next();

    expect(fetchFn).toHaveBeenCalledWith(expect.stringContaining("matchType=domain"), expect.anything());
  });

  it("zwraca pusta liste, gdy body jest pusty (brak snapshotow)", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ body: Buffer.from("") }));
    const adapter = new WaybackAdapter({ enabled: true, fetchFn });

    const records = [];
    for await (const record of adapter.search({ raw: "https://nosuch.example/page", type: "url", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }
    expect(records).toHaveLength(0);
  });

  it("rzuca AdapterHttpError przy odpowiedzi 429", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ status: 429, body: Buffer.from("") }));
    const adapter = new WaybackAdapter({ enabled: true, fetchFn });

    const iterator = adapter.search({ raw: "example.com", type: "domain", hasWildcards: false }, fakeContext());
    await expect(iterator.next()).rejects.toThrow(AdapterHttpError);
  });

  it("odrzuca zapytania innego typu niz domain/url", () => {
    const adapter = new WaybackAdapter({ enabled: true });
    const validation = adapter.validateQuery({ raw: "test@example.com", type: "email", hasWildcards: false });
    expect(validation.ok).toBe(false);
  });

  it("isConfigured() odzwierciedla flage ADAPTER_WAYBACK_ENABLED", () => {
    expect(new WaybackAdapter({ enabled: true }).isConfigured()).toBe(true);
    expect(new WaybackAdapter({ enabled: false }).isConfigured()).toBe(false);
  });
});
