import { createHash } from "node:crypto";
import { normalizeText } from "./normalize.js";

export type FingerprintType = "id" | "url" | "content" | "simhash";

/** Warstwa 1: identyfikator rekordu w ramach zrodla. Najsilniejszy sygnal. */
export function fingerprintBySourceId(sourceId: string, sourceRecordId: string): string {
  return sha256(`id:${sourceId}:${sourceRecordId}`);
}

/** Warstwa 1: kanoniczny URL (po normalizeUrl - wywolujacy normalizuje przed wywolaniem). */
export function fingerprintByUrl(canonicalUrl: string): string {
  return sha256(`url:${canonicalUrl}`);
}

/**
 * Warstwa 1: stabilny JSON surowego rekordu zrodlowego. Uzywane, gdy brak
 * sourceRecordId i URL (rzadkie, np. niektore wpisy breach-data).
 */
export function fingerprintByStableJson(raw: unknown): string {
  return sha256(`raw:${stableStringify(raw)}`);
}

/**
 * Warstwa 1: trescia - TYLKO dla kind=document/paste. Nigdy dla encji typu
 * osoba/domena, gdzie identyczna trescia moglaby bledne polaczyc rozne
 * rekordy o tej samej (powtarzalnej) wartosci.
 */
export function fingerprintByContent(normalizedText: string): string {
  return sha256(`content:${normalizedText}`);
}

function sha256(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** JSON.stringify z posortowanymi kluczami - deterministyczny niezaleznie od kolejnosci wstawiania. */
function stableStringify(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

// ---------------------------------------------------------------------------
// Warstwa 3: podobienstwo trescia (SimHash 64-bit, shingle 5-slowowe)
// ---------------------------------------------------------------------------

const SIMHASH_BITS = 64;
const SHINGLE_SIZE = 5;

/** Oblicza SimHash 64-bit dla tekstu. Uzywany TYLKO do wykrywania podobnych, nie identycznych, dokumentow. */
export function computeSimHash(text: string): bigint {
  const normalized = normalizeText(text).toLowerCase();
  const words = normalized.split(/\s+/).filter(Boolean);
  const shingles = buildShingles(words, SHINGLE_SIZE);

  const weights = new Array<number>(SIMHASH_BITS).fill(0);
  for (const shingle of shingles) {
    const hash = BigInt(`0x${sha256(shingle).slice(0, 16)}`); // 64 bitow z sha256
    for (let bit = 0; bit < SIMHASH_BITS; bit++) {
      const bitSet = (hash >> BigInt(bit)) & 1n;
      weights[bit]! += bitSet === 1n ? 1 : -1;
    }
  }

  let result = 0n;
  for (let bit = 0; bit < SIMHASH_BITS; bit++) {
    if (weights[bit]! > 0) result |= 1n << BigInt(bit);
  }
  return result;
}

function buildShingles(words: string[], size: number): string[] {
  if (words.length < size) return [words.join(" ")];
  const shingles: string[] = [];
  for (let i = 0; i <= words.length - size; i++) {
    shingles.push(words.slice(i, i + size).join(" "));
  }
  return shingles;
}

export function hammingDistance(a: bigint, b: bigint): number {
  let xor = a ^ b;
  let distance = 0;
  while (xor !== 0n) {
    distance += Number(xor & 1n);
    xor >>= 1n;
  }
  return distance;
}

/** Prog uznawany za "prawdopodobnie podobne" - link_type='similar', NIGDY automatyczne scalenie. */
export const SIMHASH_SIMILARITY_HAMMING_THRESHOLD = 3;

export function simHashToHex(hash: bigint): string {
  return hash.toString(16).padStart(16, "0");
}
