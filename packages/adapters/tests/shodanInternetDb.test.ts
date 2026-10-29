import { describe, expect, it, vi } from "vitest";
import type { SafeFetchResult } from "@unified-osint/core";
import { AdapterHttpError } from "@unified-osint/core";
import { ShodanInternetDbAdapter } from "../src/shodanInternetDb.js";

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
    finalUrl: "https://internetdb.shodan.io/1.1.1.1",
    ...overrides,
  };
}

describe("ShodanInternetDbAdapter", () => {
  it("zwraca znormalizowany rekord ekspozycji dla IP z danymi", async () => {
    const body = JSON.stringify({
      ip: "1.1.1.1",
      ports: [53, 80, 443],
      hostnames: ["one.one.one.one"],
      cpes: ["cpe:/a:cloudflare:cloudflare"],
      tags: ["pqc"],
      vulns: [],
    });
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ body: Buffer.from(body) }));
    const adapter = new ShodanInternetDbAdapter({ enabled: true, fetchFn });

    const records = [];
    for await (const record of adapter.search({ raw: "1.1.1.1", type: "ip", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }

    expect(records).toHaveLength(1);
    expect(records[0]!.attrs.ports).toEqual([53, 80, 443]);
    expect(records[0]!.attrs.hostnames).toEqual(["one.one.one.one"]);
  });

  it("traktuje 404 jako brak danych, nie jako blad", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      fakeResult({ status: 404, body: Buffer.from(JSON.stringify({ detail: "No information available" })) })
    );
    const adapter = new ShodanInternetDbAdapter({ enabled: true, fetchFn });

    const records = [];
    for await (const record of adapter.search({ raw: "192.0.2.123", type: "ip", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }
    expect(records).toHaveLength(0);
  });

  it("rzuca AdapterHttpError przy odpowiedzi 503", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ status: 503, body: Buffer.from("") }));
    const adapter = new ShodanInternetDbAdapter({ enabled: true, fetchFn });

    const iterator = adapter.search({ raw: "1.1.1.1", type: "ip", hasWildcards: false }, fakeContext());
    await expect(iterator.next()).rejects.toThrow(AdapterHttpError);
  });

  it("odrzuca zapytania innego typu niz ip", () => {
    const adapter = new ShodanInternetDbAdapter({ enabled: true });
    const validation = adapter.validateQuery({ raw: "example.com", type: "domain", hasWildcards: false });
    expect(validation.ok).toBe(false);
  });

  it("isConfigured() odzwierciedla flage ADAPTER_SHODAN_INTERNETDB_ENABLED", () => {
    expect(new ShodanInternetDbAdapter({ enabled: true }).isConfigured()).toBe(true);
    expect(new ShodanInternetDbAdapter({ enabled: false }).isConfigured()).toBe(false);
  });
});
