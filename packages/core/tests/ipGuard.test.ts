import { describe, expect, it } from "vitest";
import { isDisallowedIp } from "../src/net/ipGuard.js";

describe("isDisallowedIp", () => {
  it("blokuje loopback IPv4 i IPv6", () => {
    expect(isDisallowedIp("127.0.0.1")).toBe(true);
    expect(isDisallowedIp("::1")).toBe(true);
  });

  it("blokuje sieci prywatne RFC1918", () => {
    expect(isDisallowedIp("10.0.0.5")).toBe(true);
    expect(isDisallowedIp("172.16.0.5")).toBe(true);
    expect(isDisallowedIp("192.168.1.5")).toBe(true);
  });

  it("blokuje link-local, w tym metadane chmurowe 169.254.169.254", () => {
    expect(isDisallowedIp("169.254.169.254")).toBe(true);
    expect(isDisallowedIp("169.254.1.1")).toBe(true);
  });

  it("blokuje IPv4-mapped IPv6 wskazujace na adres prywatny", () => {
    expect(isDisallowedIp("::ffff:127.0.0.1")).toBe(true);
    expect(isDisallowedIp("::ffff:10.0.0.1")).toBe(true);
  });

  it("blokuje IPv6 unique-local i link-local", () => {
    expect(isDisallowedIp("fc00::1")).toBe(true);
    expect(isDisallowedIp("fe80::1")).toBe(true);
  });

  it("dopuszcza publiczne adresy IPv4/IPv6", () => {
    expect(isDisallowedIp("8.8.8.8")).toBe(false);
    expect(isDisallowedIp("1.1.1.1")).toBe(false);
    expect(isDisallowedIp("2606:4700:4700::1111")).toBe(false);
  });

  it("odrzuca wejscie, ktore nie jest poprawnym adresem IP (fail closed)", () => {
    expect(isDisallowedIp("not-an-ip")).toBe(true);
  });
});
