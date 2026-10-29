import { describe, expect, it, vi } from "vitest";
import type { SafeFetchResult } from "@unified-osint/core";
import { AdapterHttpError } from "@unified-osint/core";
import { CrtShAdapter } from "../src/crtsh.js";

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
    finalUrl: "https://crt.sh/?q=example.com&output=json",
    ...overrides,
  };
}

describe("CrtShAdapter", () => {
  it("zwraca znormalizowane rekordy certyfikatow i deduplikuje po id", async () => {
    const body = JSON.stringify([
      {
        issuer_ca_id: 1,
        issuer_name: "C=US, O=Let's Encrypt, CN=R3",
        common_name: "example.com",
        name_value: "example.com\nwww.example.com",
        id: 100,
        not_before: "2024-01-01T00:00:00",
        not_after: "2024-04-01T00:00:00",
        serial_number: "abc123",
        result_count: 2,
      },
      {
        issuer_ca_id: 1,
        issuer_name: "C=US, O=Let's Encrypt, CN=R3",
        common_name: "example.com",
        name_value: "example.com\nwww.example.com",
        id: 100,
        not_before: "2024-01-01T00:00:00",
        not_after: "2024-04-01T00:00:00",
        serial_number: "abc123",
        result_count: 2,
      },
    ]);
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ body: Buffer.from(body) }));
    const adapter = new CrtShAdapter({ enabled: true, fetchFn });

    const records = [];
    for await (const record of adapter.search({ raw: "example.com", type: "domain", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }

    expect(records).toHaveLength(1);
    expect(records[0]!.attrs.subjectAltNames).toEqual(["example.com", "www.example.com"]);
    expect(fetchFn).toHaveBeenCalledWith(
      expect.stringContaining("crt.sh/?q=example.com&output=json"),
      expect.anything()
    );
  });

  it("zwraca pusta liste, gdy body jest pusty", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ body: Buffer.from("") }));
    const adapter = new CrtShAdapter({ enabled: true, fetchFn });

    const records = [];
    for await (const record of adapter.search({ raw: "nosuchdomain.example", type: "domain", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }
    expect(records).toHaveLength(0);
  });

  it("rzuca AdapterHttpError przy odpowiedzi 502", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ status: 502, body: Buffer.from("") }));
    const adapter = new CrtShAdapter({ enabled: true, fetchFn });

    const iterator = adapter.search({ raw: "example.com", type: "domain", hasWildcards: false }, fakeContext());
    await expect(iterator.next()).rejects.toThrow(AdapterHttpError);
  });

  it("odrzuca zapytania innego typu niz domain", () => {
    const adapter = new CrtShAdapter({ enabled: true });
    const validation = adapter.validateQuery({ raw: "test@example.com", type: "email", hasWildcards: false });
    expect(validation.ok).toBe(false);
  });

  it("isConfigured() odzwierciedla flage ADAPTER_CRTSH_ENABLED", () => {
    expect(new CrtShAdapter({ enabled: true }).isConfigured()).toBe(true);
    expect(new CrtShAdapter({ enabled: false }).isConfigured()).toBe(false);
  });
});
