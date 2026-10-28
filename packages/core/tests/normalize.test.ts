import { describe, expect, it } from "vitest";
import { normalizeDomain, normalizeUrl, normalizeText, normalizeEmail } from "../src/dedup/normalize.js";

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
