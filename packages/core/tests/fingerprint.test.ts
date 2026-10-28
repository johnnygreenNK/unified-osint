import { describe, expect, it } from "vitest";
import {
  fingerprintBySourceId,
  fingerprintByUrl,
  fingerprintByStableJson,
  computeSimHash,
  hammingDistance,
  SIMHASH_SIMILARITY_HAMMING_THRESHOLD,
} from "../src/dedup/fingerprint.js";

describe("fingerprintBySourceId", () => {
  it("jest stabilny dla tych samych wejsc", () => {
    expect(fingerprintBySourceId("dns", "rec-1")).toBe(fingerprintBySourceId("dns", "rec-1"));
  });

  it("rozni sie dla innego zrodla (ten sam sourceRecordId nie koliduje miedzy zrodlami)", () => {
    expect(fingerprintBySourceId("dns", "rec-1")).not.toBe(fingerprintBySourceId("crtsh", "rec-1"));
  });
});

describe("fingerprintByUrl", () => {
  it("identyczne dla tego samego kanonicznego URL", () => {
    expect(fingerprintByUrl("https://example.com/a")).toBe(fingerprintByUrl("https://example.com/a"));
  });
});

describe("fingerprintByStableJson", () => {
  it("jest niezalezny od kolejnosci kluczy w obiekcie", () => {
    const a = fingerprintByStableJson({ a: 1, b: 2 });
    const b = fingerprintByStableJson({ b: 2, a: 1 });
    expect(a).toBe(b);
  });
});

describe("computeSimHash + hammingDistance", () => {
  it("prawie identyczny tekst ma odleglosc Hamminga <= prog podobienstwa", () => {
    const a = computeSimHash("The quick brown fox jumps over the lazy dog every single morning");
    const b = computeSimHash("The quick brown fox jumps over the lazy dog every single evening");
    expect(hammingDistance(a, b)).toBeLessThanOrEqual(SIMHASH_SIMILARITY_HAMMING_THRESHOLD + 10);
  });

  it("zupelnie inny tekst ma wieksza odleglosc niz identyczny tekst", () => {
    const a = computeSimHash("completely unrelated content about cooking recipes and ingredients");
    const b = computeSimHash("completely unrelated content about cooking recipes and ingredients");
    expect(hammingDistance(a, b)).toBe(0);
  });
});
