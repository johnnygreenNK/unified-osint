import { describe, expect, it } from "vitest";
import { createDefaultRegistry } from "../src/registry.js";
import { DemoAdapter } from "../src/demo.js";
import { DnsAdapter } from "../src/dns.js";
import { createNotConfiguredStub } from "../src/notConfiguredStub.js";

describe("StaticAdapterRegistry / createDefaultRegistry", () => {
  it("rejestruje wszystkie oczekiwane adaptery pod ich id", () => {
    const registry = createDefaultRegistry();
    const ids = registry.list().map((a) => a.descriptor.id);
    expect(ids.sort()).toEqual(["demo", "dns", "epieos", "intelx", "snusbase"].sort());
  });

  it("get() zwraca ten sam adapter co list() dla danego id", () => {
    const registry = createDefaultRegistry();
    for (const adapter of registry.list()) {
      expect(registry.get(adapter.descriptor.id)).toBe(adapter);
    }
  });

  it("get() zwraca undefined dla nieznanego id", () => {
    const registry = createDefaultRegistry();
    expect(registry.get("nieistniejacy-adapter")).toBeUndefined();
  });

  it("demo i dns sa skonfigurowane, platne zrodla bez klucza - nie", () => {
    const registry = createDefaultRegistry();
    expect(registry.get("demo")?.isConfigured()).toBe(true);
    expect(registry.get("dns")?.isConfigured()).toBe(true);
    expect(registry.get("snusbase")?.isConfigured()).toBe(false);
    expect(registry.get("intelx")?.isConfigured()).toBe(false);
    expect(registry.get("epieos")?.isConfigured()).toBe(false);
  });
});

describe("createNotConfiguredStub", () => {
  const stub = createNotConfiguredStub({
    id: "test-stub",
    name: "Test Stub",
    category: "breach_data",
    requiredEnvVars: ["TEST_STUB_API_KEY"],
    capabilities: [{ queryType: "email", supportsWildcards: false, maxResults: 10 }],
    cost: { unit: "credit", estimatedCostPerQuery: 1, unknown: true },
    verificationNote: "test",
  });

  it("nigdy nie zglasza sie jako skonfigurowany", () => {
    expect(stub.isConfigured()).toBe(false);
  });

  it("healthCheck zawsze zwraca not_configured, nigdy ok", async () => {
    const result = await stub.healthCheck();
    expect(result.ok).toBe(false);
    expect(result.errorCode).toBe("not_configured");
  });

  it("validateQuery odmawia kazdego zapytania", () => {
    const validation = stub.validateQuery({
      raw: "test@example.com",
      type: "email",
      norm: "test@example.com",
      normVersion: 1,
    });
    expect(validation.ok).toBe(false);
  });

  it("search() rzuca blad, jesli zostanie wywolane mimo isConfigured() === false", async () => {
    const iterator = stub.search(
      { raw: "test@example.com", type: "email", norm: "test@example.com", normVersion: 1 },
      { signal: new AbortController().signal } as never
    );
    await expect(iterator.next()).rejects.toThrow();
  });
});

describe("DemoAdapter i DnsAdapter - zdrowie i konfiguracja", () => {
  it("DemoAdapter jest skonfigurowany i zdrowy bez zadnej konfiguracji", async () => {
    const demo = new DemoAdapter();
    expect(demo.isConfigured()).toBe(true);
    const health = await demo.healthCheck();
    expect(health.ok).toBe(true);
  });

  it("DnsAdapter jest skonfigurowany i obsluguje tylko domeny, bez wildcardow", () => {
    const dnsAdapter = new DnsAdapter();
    expect(dnsAdapter.isConfigured()).toBe(true);
    const caps = dnsAdapter.getCapabilities();
    expect(caps).toHaveLength(1);
    expect(caps[0]?.queryType).toBe("domain");
    expect(caps[0]?.supportsWildcards).toBe(false);
  });
});
