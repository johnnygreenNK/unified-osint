import { describe, expect, it, vi } from "vitest";
import type { SafeFetchResult } from "@unified-osint/core";
import { AdapterHttpError } from "@unified-osint/core";
import { HudsonRockAdapter } from "../src/hudsonrock.js";

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
    finalUrl: "https://api.hudsonrock.com/json/v3/search-by-login/emails",
    ...overrides,
  };
}

describe("HudsonRockAdapter", () => {
  it("maskuje plaintext hasla w credentials i zwraca znormalizowane rekordy", async () => {
    const body = JSON.stringify({
      data: [
        {
          stealer: "RedLine",
          date_compromised: "2024-05-01T00:00:00Z",
          ip: "1.2.3.4",
          computer_name: "DESKTOP-ABC",
          operating_system: "Windows 10",
          credentials: [
            { url: "https://example.com/login", domain: "example.com", username: "test@example.com", password: "plaintext", type: "user" },
          ],
        },
      ],
      nextCursor: null,
    });
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ body: Buffer.from(body) }));
    const adapter = new HudsonRockAdapter({ apiKey: "test-key", baseUrl: "https://api.hudsonrock.com", fetchFn });

    const records = [];
    for await (const record of adapter.search({ raw: "test@example.com", type: "email", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }

    expect(records).toHaveLength(1);
    const record = records[0]!;
    expect(record.kind).toBe("infostealer_infection");
    expect(record.attrs.stealer).toBe("RedLine");
    const credentials = record.attrs.credentials as Array<Record<string, unknown>>;
    expect(credentials[0]!.passwordMasked).toBe(true);
    expect(credentials[0]!.password).toBeUndefined();
    expect(credentials[0]!.username).toBe("test@example.com");

    expect(fetchFn).toHaveBeenCalledWith(
      "https://api.hudsonrock.com/json/v3/search-by-login/emails",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({ "api-key": "test-key" }),
        body: JSON.stringify({ logins: ["test@example.com"] }),
      })
    );
  });

  it("uzywa endpointu usernames dla zapytan typu username", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ body: Buffer.from(JSON.stringify({ data: [] })) }));
    const adapter = new HudsonRockAdapter({ apiKey: "test-key", baseUrl: "https://api.hudsonrock.com", fetchFn });

    const iterator = adapter.search({ raw: "testuser", type: "username", hasWildcards: false }, fakeContext());
    await iterator.next();

    expect(fetchFn).toHaveBeenCalledWith(
      "https://api.hudsonrock.com/json/v3/search-by-login/usernames",
      expect.anything()
    );
  });

  it("rzuca AdapterHttpError przy odpowiedzi 403", async () => {
    const fetchFn = vi.fn().mockResolvedValue(fakeResult({ status: 403, body: Buffer.from("{}") }));
    const adapter = new HudsonRockAdapter({ apiKey: "bad-key", baseUrl: "https://api.hudsonrock.com", fetchFn });

    const iterator = adapter.search({ raw: "test@example.com", type: "email", hasWildcards: false }, fakeContext());
    await expect(iterator.next()).rejects.toThrow(AdapterHttpError);
  });

  it("odrzuca zapytania z wildcardami", () => {
    const adapter = new HudsonRockAdapter({ apiKey: "test-key", baseUrl: "https://api.hudsonrock.com" });
    const validation = adapter.validateQuery({ raw: "test*", type: "email", hasWildcards: true });
    expect(validation.ok).toBe(false);
  });

  it("isConfigured() jest false bez klucza API", () => {
    const adapter = new HudsonRockAdapter({ apiKey: "", baseUrl: "https://api.hudsonrock.com" });
    expect(adapter.isConfigured()).toBe(false);
  });
});
