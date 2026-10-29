import { describe, expect, it } from "vitest";
import {
  normalizeDomain,
  normalizeUrl,
  normalizeText,
  normalizeEmail,
  normalizeIp,
  normalizePhone,
} from "../src/dedup/normalize.js";

describe("normalizeDomain", () => {
  it("lowercases and strips trailing dot", () => {
    expect(normalizeDomain("Example.COM.")).toBe("example.com");
  });
});

describe("normalizeUrl", () => {
  it("usuwa domyslny port, fragment i sortuje parametry", () => {
    expect(normalizeUrl("HTTPS://Example.com:443/foo?b=2&a=1#section")).toBe(
      "https://example.com/foo?a=1&b=2"
    );
  });

  it("usuwa TYLKO parametry sledzace z allowlisty", () => {
    expect(normalizeUrl("https://example.com/?utm_source=x&id=123")).toBe(
      "https://example.com/?id=123"
    );
  });

  it("nie usuwa nieznanych parametrow, bo moga zmieniac zasob", () => {
    const result = normalizeUrl("https://example.com/?page=2");
    expect(result).toContain("page=2");
  });
});

describe("normalizeText", () => {
  it("zwija biale znaki, zachowuje wielkosc liter", () => {
    expect(normalizeText("  Hello   World  ")).toBe("Hello World");
  });
});

describe("normalizeEmail", () => {
  it("lowercase tylko domeny, nie czesci lokalnej (kropki/plusy zachowane)", () => {
    expect(normalizeEmail("John.Doe+test@EXAMPLE.COM")).toBe("john.doe+test@example.com");
  });
});

describe("normalizeIp", () => {
  it("akceptuje IPv4 bez zmian", () => {
    expect(normalizeIp("203.0.113.42")).toBe("203.0.113.42");
  });

  it("lowercase IPv6", () => {
    expect(normalizeIp("2001:DB8::1")).toBe("2001:db8::1");
  });

  it("odrzuca nieprawidlowy adres (fail closed)", () => {
    expect(normalizeIp("not-an-ip")).toBeNull();
    expect(normalizeIp("999.999.999.999")).toBeNull();
  });
});

describe("normalizePhone", () => {
  it("zachowuje prefiks + i cyfry, usuwa separatory", () => {
    expect(normalizePhone("+48 123-456-789")).toBe("+48123456789");
  });

  it("zamienia prefiks 00 na +", () => {
    expect(normalizePhone("0048123456789")).toBe("+48123456789");
  });

  it("odrzuca numery zbyt krotkie, zamiast zgadywac kod kraju", () => {
    expect(normalizePhone("12345")).toBeNull();
  });
});
