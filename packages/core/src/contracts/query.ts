/**
 * Typy zapytan obslugiwane przez platforme.
 *
 * Swiadomie BRAK typu "password": wyszukiwanie plaintext/wildcard po hasle
 * w bazach wyciekow jest poza zakresem tego narzedzia. Adaptery breach-data
 * (Snusbase, HIBP) przyjmuja tylko EMAIL lub USERNAME i odpowiadaja
 * "czy i gdzie wystapil wyciek", nigdy nie sluza do masowego wydobywania
 * hasel po wzorcu.
 */
export const QUERY_TYPES = [
  "email",
  "username",
  "name",
  "domain",
  "ip",
  "phone",
  "hash",
  "url",
  "text",
] as const;

export type QueryType = (typeof QUERY_TYPES)[number];

export interface SearchQuery {
  /** Surowy tekst wpisany przez uzytkownika, bez modyfikacji. */
  raw: string;
  /** Typ zapytania - wykryty automatycznie albo wybrany recznie w UI. */
  type: QueryType;
  /**
   * Czy raw zawiera wildcardy UI (`*` = dowolny ciag, `?` = jeden znak).
   * Kazdy adapter sam decyduje, czy i jak je obsluzyc (patrz hasWildcards
   * w validateQuery). Adaptery bez wsparcia dla wildcardow MUSZA odrzucic
   * zapytanie z jasnym komunikatem, a nie przetworzyc je po cichu literalnie.
   */
  hasWildcards: boolean;
}

/** Minimalna liczba znakow literalnych (bez wildcardow) wymagana do akceptacji zapytania z `*`/`?`. */
export const MIN_LITERAL_CHARS_FOR_WILDCARD_QUERY = 3;

const WILDCARD_CHARS = /[*?]/;

export function detectWildcards(raw: string): boolean {
  return WILDCARD_CHARS.test(raw);
}

export function countLiteralChars(raw: string): number {
  return raw.replace(/[*?]/g, "").length;
}

/** Heurystyka wykrywania typu zapytania, uzywana jako domyslna sugestia w UI. */
export function detectQueryType(raw: string): QueryType {
  const value = raw.trim();
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.replace(/[*?]/g, "x"))) return "email";
  if (/^\+?[0-9()\-\s]{7,}$/.test(value)) return "phone";
  if (/^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$/.test(value)) return "hash";
  if (/^https?:\/\//i.test(value)) return "url";
  if (/^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]{3,}$/.test(value) && value.includes(".") === false) {
    // bardzo zgrubna heurystyka IPv4/IPv6 - ostateczna walidacja w adapterze
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value) || value.includes(":")) return "ip";
  }
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return "ip";
  if (/^[a-z0-9*?-]+(\.[a-z0-9*?-]+)+$/i.test(value) && !value.includes(" ")) return "domain";
  if (/^[a-zA-Z0-9_.\-*?]{3,32}$/.test(value) && !value.includes(" ")) return "username";
  if (/^[a-zA-ZÀ-ſ*?\s]{2,60}$/.test(value) && value.includes(" ")) return "name";
  return "text";
}

export function buildSearchQuery(raw: string, type?: QueryType): SearchQuery {
  const trimmed = raw.trim();
  return {
    raw: trimmed,
    type: type ?? detectQueryType(trimmed),
    hasWildcards: detectWildcards(trimmed),
  };
}
