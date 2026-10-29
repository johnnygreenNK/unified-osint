import { describe, expect, it } from "vitest";
import { extractCorrelationKeys } from "../src/dedup/dedupEngine.js";
import type { AdapterRecord } from "../src/contracts/adapter.js";

function record(attrs: Record<string, unknown>): AdapterRecord {
  return {
    sourceRecordId: "r1",
    canonicalUrl: null,
    kind: "breach_record",
    title: "test",
    summary: null,
    attrs,
    observedAt: null,
    raw: null,
  };
}

describe("extractCorrelationKeys", () => {
  it("wydobywa i normalizuje email, username, ip, telefon, domene", () => {
    const keys = extractCorrelationKeys(
      record({
        email: "Test@Example.COM",
        username: "TestUser",
        lastip: "203.0.113.42",
        phone: "+48 123-456-789",
        domain: "Example.com.",
      })
    );
    expect(keys).toEqual(
      expect.arrayContaining([
        { type: "email", value: "test@example.com" },
        { type: "username", value: "testuser" },
        { type: "ip", value: "203.0.113.42" },
        { type: "phone", value: "+48123456789" },
        { type: "domain", value: "example.com" },
      ])
    );
  });

  it("pomija atrybuty puste/niepoprawne bez rzucania bledu", () => {
    const keys = extractCorrelationKeys(record({ email: "", lastip: "not-an-ip", username: 123 }));
    expect(keys).toEqual([]);
  });

  it("uzywa pierwszego obecnego aliasu i nie duplikuje typu", () => {
    const keys = extractCorrelationKeys(record({ ip: "203.0.113.1", lastip: "203.0.113.2" }));
    expect(keys.filter((k) => k.type === "ip")).toHaveLength(1);
    expect(keys[0]).toEqual({ type: "ip", value: "203.0.113.1" });
  });

  it("zwraca puste bez zadnych znanych atrybutow", () => {
    expect(extractCorrelationKeys(record({ breachTable: "x" }))).toEqual([]);
  });
});
