/**
 * Normalizacja per-typ-pola (NIE globalna). Kazda funkcja dokumentuje,
 * co zachowuje i co zmienia - patrz docs/deduplication.md dla pelnego
 * uzasadnienia kazdej decyzji.
 */

/** Wersja algorytmu normalizacji. Zmiana = nowa wersja, nigdy cicha mutacja. */
export const NORMALIZATION_VERSION = 1;

/** Tylko parametry sledzace, ktore nie zmieniaja zasobu ani uprawnien. */
const TRACKING_PARAM_ALLOWLIST = new Set([
  "utm_source",
  "utm_medium",
  "utm_campaign",
  "utm_term",
  "utm_content",
  "utm_id",
  "fbclid",
  "gclid",
  "gclsrc",
  "dclid",
  "msclkid",
  "mc_cid",
  "mc_eid",
  "ref",
  "ref_src",
  "igshid",
]);

/** Domena: IDNA/punycode przez URL API, lowercase, bez koncowej kropki. */
export function normalizeDomain(input: string): string {
  const trimmed = input.trim().toLowerCase().replace(/\.$/, "");
  try {
    // new URL wymusza IDNA/punycode dla hosta.
    const url = new URL(`http://${trimmed}`);
    return url.hostname.replace(/\.$/, "");
  } catch {
    return trimmed;
  }
}

/**
 * URL: lowercase schemat+host, domyslny port usuniety, fragment usuniety,
 * parametry sortowane, TYLKO parametry z allowlisty sledzenia usuniete.
 * Nieznane parametry zostaja - moga zmieniac zasob (np. ?id=123).
 */
export function normalizeUrl(input: string): string {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return input.trim();
  }

  url.protocol = url.protocol.toLowerCase();
  url.hostname = url.hostname.toLowerCase();
  url.hash = "";

  const defaultPort = url.protocol === "https:" ? "443" : url.protocol === "http:" ? "80" : null;
  if (defaultPort && url.port === defaultPort) url.port = "";

  const params = Array.from(url.searchParams.entries()).filter(
    ([key]) => !TRACKING_PARAM_ALLOWLIST.has(key.toLowerCase())
  );
  params.sort(([a], [b]) => a.localeCompare(b));
  url.search = "";
  for (const [key, value] of params) url.searchParams.append(key, value);

  let result = url.toString();
  if (result.endsWith("/") && url.pathname === "/" && !url.search) {
    // zachowaj pojedynczy slash root, ale usun zbedny trailing slash dla innych sciezek
  } else if (url.pathname !== "/" && result.endsWith("/") && !url.search) {
    result = result.slice(0, -1);
  }
  return result;
}

/** Tekst: Unicode NFKC + zwiniecie bialych znakow. Wielkosc liter ZACHOWANA. */
export function normalizeText(input: string): string {
  return input.normalize("NFKC").replace(/\s+/g, " ").trim();
}

/** E-mail: lowercase domeny; czesc lokalna lowercase, ale bez usuwania kropek/plusow. */
export function normalizeEmail(input: string): string {
  const trimmed = input.trim();
  const atIndex = trimmed.lastIndexOf("@");
  if (atIndex === -1) return trimmed.toLowerCase();
  const local = trimmed.slice(0, atIndex);
  const domain = trimmed.slice(atIndex + 1);
  return `${local.toLowerCase()}@${normalizeDomain(domain)}`;
}

/** Data: ISO-8601 UTC. Oryginalna strefa powinna byc zachowana osobno w attrs przez wywolujacego. */
export function normalizeDateToUtcIso(input: string | number | Date): string | null {
  const date = new Date(input);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}
