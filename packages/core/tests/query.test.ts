import { describe, expect, it } from "vitest";
import {
  detectQueryType,
  detectWildcards,
  countLiteralChars,
  buildSearchQuery,
} from "../src/contracts/query.js";

describe("detectQueryType", () => {
  it("wykrywa email", () => {
    expect(detectQueryType("jan.kowalski@example.com")).toBe("email");
  });
  it("wykrywa domene", () => {
    expect(detectQueryType("example.com")).toBe("domain");
  });
  it("wykrywa adres IPv4", () => {
    expect(detectQueryType("192.168.1.1")).toBe("ip");
  });
  it("wykrywa hash sha256", () => {
    expect(detectQueryType("a".repeat(64))).toBe("hash");
  });
  it("wykrywa URL", () => {
    expect(detectQueryType("https://example.com/path")).toBe("url");
  });
  it("domyslnie traktuje jako text", () => {
    expect(detectQueryType("to jest dluzsze zapytanie tekstowe 123")).toBe("text");
  });
});

describe("wildcardy", () => {
  it("wykrywa gwiazdke i znak zapytania", () => {
    expect(detectWildcards("jan*kowalski")).toBe(true);
    expect(detectWildcards("jan?kowalski")).toBe(true);
    expect(detectWildcards("jankowalski")).toBe(false);
  });

  it("liczy znaki literalne bez wildcardow", () => {
    expect(countLiteralChars("ab*cd??ef")).toBe(6);
  });
});

describe("buildSearchQuery", () => {
  it("przycina biale znaki i wykrywa typ automatycznie", () => {
    const q = buildSearchQuery("  example.com  ");
    expect(q.raw).toBe("example.com");
    expect(q.type).toBe("domain");
    expect(q.hasWildcards).toBe(false);
  });

  it("respektuje recznie podany typ", () => {
    const q = buildSearchQuery("example.com", "text");
    expect(q.type).toBe("text");
  });
});
