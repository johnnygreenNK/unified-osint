import { describe, expect, it, vi } from "vitest";
import type { SafeFetchResult } from "@unified-osint/core";
import { AdapterHttpError } from "@unified-osint/core";
import { RdapAdapter } from "../src/rdap.js";

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
    finalUrl: "https://rdap.org/domain/example.com",
    ...overrides,
  };
}

describe("RdapAdapter", () => {
  it("zwraca znormalizowany rekord dla zapytania typu domain", async () => {
    const body = JSON.stringify({
      objectClassName: "domain",
      handle: "2336799_DOMAIN_COM-VRSN",
      ldhName: "EXAMPLE.COM",
      status: ["client delete prohibited"],
      events: [{ eventAction: "registration", eventDate: "1995-08-14T04:00:00Z" }],
      nameservers: [{ ldhName: "a.iana-servers.net" }],
    });
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ body: Buffer.from(body) }));
    const adapter = new RdapAdapter({ enabled: true, fetchFn });

    const records = [];
    for await (const record of adapter.search({ raw: "example.com", type: "domain", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }

    expect(records).toHaveLength(1);
    expect(records[0]!.attrs.handle).toBe("2336799_DOMAIN_COM-VRSN");
    expect(records[0]!.observedAt).toBe("1995-08-14T04:00:00.000Z");
    expect(fetchFn).toHaveBeenCalledWith(expect.stringContaining("/domain/example.com"), expect.anything());
  });

  it("uzywa endpointu /ip/ dla zapytan typu ip", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ body: Buffer.from(JSON.stringify({ objectClassName: "ip network" })) }));
    const adapter = new RdapAdapter({ enabled: true, fetchFn });

    const iterator = adapter.search({ raw: "1.1.1.1", type: "ip", hasWildcards: false }, fakeContext());
    await iterator.next();

    expect(fetchFn).toHaveBeenCalledWith(expect.stringContaining("/ip/1.1.1.1"), expect.anything());
  });

  it("traktuje 404 jako brak znanego serwera RDAP, nie jako blad", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ status: 404, body: Buffer.from("") }));
    const adapter = new RdapAdapter({ enabled: true, fetchFn });

    const records = [];
    for await (const record of adapter.search({ raw: "example.com", type: "domain", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }
    expect(records).toHaveLength(0);
  });

  it("rzuca AdapterHttpError przy odpowiedzi 429", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ status: 429, headers: { "retry-after": "5" }, body: Buffer.from("{}") }));
    const adapter = new RdapAdapter({ enabled: true, fetchFn });

    const iterator = adapter.search({ raw: "example.com", type: "domain", hasWildcards: false }, fakeContext());
    try {
      await iterator.next();
      expect.fail("powinno rzucic");
    } catch (err) {
      expect(err).toBeInstanceOf(AdapterHttpError);
      expect((err as AdapterHttpError).retryAfterHeader).toBe("5");
    }
  });

  it("odrzuca zapytania innego typu niz domain/ip", () => {
    const adapter = new RdapAdapter({ enabled: true });
    const validation = adapter.validateQuery({ raw: "testuser", type: "username", hasWildcards: false });
    expect(validation.ok).toBe(false);
  });

  it("isConfigured() odzwierciedla flage ADAPTER_RDAP_ENABLED", () => {
    expect(new RdapAdapter({ enabled: true }).isConfigured()).toBe(true);
    expect(new RdapAdapter({ enabled: false }).isConfigured()).toBe(false);
  });
});
