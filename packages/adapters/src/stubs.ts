import type { SourceAdapter } from "@unified-osint/core";
import { createNotConfiguredStub } from "./notConfiguredStub.js";

/**
 * Konkretne instancje adapterow-zaslepek dla zrodel platnych/wymagajacych
 * weryfikacji API przed implementacja. Kazdy ma status `not_configured`
 * NIEZALEZNIE od obecnosci klucza w .env - patrz notConfiguredStub.ts.
 *
 * Gdy integracja zostanie zaimplementowana i zweryfikowana wobec
 * oficjalnej dokumentacji danego zrodla, zastap wpis w registry.ts
 * dedykowana klasa adaptera (wzorem DemoAdapter/DnsAdapter).
 */

export const intelxStub: SourceAdapter = createNotConfiguredStub({
  id: "intelx",
  name: "IntelX",
  category: "threat_intel",
  requiredEnvVars: ["INTELX_API_KEY"],
  capabilities: [
    { queryType: "email", supportsWildcards: false, maxResults: 20 },
    { queryType: "domain", supportsWildcards: false, maxResults: 20 },
    { queryType: "hash", supportsWildcards: false, maxResults: 20 },
  ],
  cost: { unit: "credit", estimatedCostPerQuery: 1, unknown: true },
  verificationNote:
    "Endpointy i zakres danych faktycznie dostepnych w planie API IntelX " +
    "wymagaja weryfikacji w oficjalnej dokumentacji przed implementacja. Nie " +
    "zaklada sie dostepu do zadnej konkretnej kategorii danych (np. 'logow'), " +
    "dopoki nie zostanie to potwierdzone w dokumentacji i przetestowane.",
});

export const epieosStub: SourceAdapter = createNotConfiguredStub({
  id: "epieos",
  name: "Epieos",
  category: "social_official_api",
  requiredEnvVars: ["EPIEOS_API_KEY"],
  capabilities: [{ queryType: "email", supportsWildcards: false, maxResults: 20 }],
  cost: { unit: "credit", estimatedCostPerQuery: 1, unknown: true },
  verificationNote:
    "Epieos nie publikuje dokumentacji API - dostep jest udzielany indywidualnie " +
    "na zadanie (plan enterprise/custom). Ten adapter zostaje `not_configured` do " +
    "momentu, gdy uzytkownik uzyska dostep API i dostawca udostepni dokumentacje " +
    "endpointow - bez tego nie da sie zweryfikowac kontraktu zgodnie z zasada " +
    "'nie wymyslaj endpointow API', wiec implementacja nie moze ruszyc. Integracja " +
    "ograniczona wylacznie do oficjalnego API (bez scrapowania UI wbrew ToS).",
});

/**
 * Zaslepki dla dostawcow intelligence z infostealerow/wyciekow, ktorych
 * publiczne strony (stan na 2026-10-29) nie udostepniaja dokumentacji API
 * bez zalogowania/konta sprzedazowego - sprawdzone bezposrednio przed
 * dodaniem tych wpisow (DeHashed: strona dokumentacji wymaga konta;
 * SpyCloud/Flare/KELA/Constella: wylacznie sprzedaz B2B z demo/kontaktem,
 * bez samoobslugowego dostepu ani publicznego opisu endpointow). Zgodnie z
 * zasada 'nie wymyslaj endpointow API' zostaja `not_configured`, dopoki
 * uzytkownik nie uzyska dostepu i dostawca nie udostepni dokumentacji.
 */
export const dehashedStub: SourceAdapter = createNotConfiguredStub({
  id: "dehashed",
  name: "DeHashed",
  category: "breach_data",
  requiredEnvVars: ["DEHASHED_API_KEY"],
  capabilities: [
    { queryType: "email", supportsWildcards: false, maxResults: 20 },
    { queryType: "username", supportsWildcards: false, maxResults: 20 },
    { queryType: "domain", supportsWildcards: false, maxResults: 20 },
  ],
  cost: { unit: "credit", estimatedCostPerQuery: 1, unknown: true },
  verificationNote:
    "DeHashed przeniosl API na wersje v2 (naglowek 'Dehashed-Api-Key' wedlug " +
    "nieoficjalnych klientow), ale pelna dokumentacja odpowiedzi/schemy jest " +
    "dostepna tylko po zalogowaniu na konto z aktywna subskrypcja Search - nie " +
    "da sie zweryfikowac kontraktu publicznie. Implementacja odlozona do czasu, " +
    "gdy uzytkownik uzyska dostep do panelu i dokumentacji.",
});

export const spycloudStub: SourceAdapter = createNotConfiguredStub({
  id: "spycloud",
  name: "SpyCloud",
  category: "threat_intel",
  requiredEnvVars: ["SPYCLOUD_API_KEY"],
  capabilities: [{ queryType: "email", supportsWildcards: false, maxResults: 20 }],
  cost: { unit: "credit", estimatedCostPerQuery: 1, unknown: true },
  verificationNote:
    "SpyCloud nie oferuje samoobslugowego dostepu API - sprzedaz wylacznie B2B " +
    "przez kontakt handlowy, bez publicznej dokumentacji endpointow. Implementacja " +
    "odlozona do czasu, gdy uzytkownik uzyska dostep i oficjalna dokumentacje.",
});

export const flareStub: SourceAdapter = createNotConfiguredStub({
  id: "flare",
  name: "Flare",
  category: "threat_intel",
  requiredEnvVars: ["FLARE_API_KEY"],
  capabilities: [{ queryType: "email", supportsWildcards: false, maxResults: 20 }],
  cost: { unit: "credit", estimatedCostPerQuery: 1, unknown: true },
  verificationNote:
    "Flare.io nie oferuje samoobslugowego dostepu API - sprzedaz wylacznie B2B " +
    "przez demo/kontakt handlowy, bez publicznej dokumentacji endpointow. " +
    "Implementacja odlozona do czasu, gdy uzytkownik uzyska dostep i oficjalna dokumentacje.",
});

export const kelaStub: SourceAdapter = createNotConfiguredStub({
  id: "kela",
  name: "KELA",
  category: "threat_intel",
  requiredEnvVars: ["KELA_API_KEY"],
  capabilities: [{ queryType: "email", supportsWildcards: false, maxResults: 20 }],
  cost: { unit: "credit", estimatedCostPerQuery: 1, unknown: true },
  verificationNote:
    "KELA (Prevent/Cyber Intelligence Platform) nie oferuje samoobslugowego " +
    "dostepu API - sprzedaz wylacznie enterprise przez kontakt handlowy, bez " +
    "publicznej dokumentacji endpointow. Implementacja odlozona do czasu, gdy " +
    "uzytkownik uzyska dostep i oficjalna dokumentacje.",
});

export const constellaStub: SourceAdapter = createNotConfiguredStub({
  id: "constella",
  name: "Constella Intelligence",
  category: "threat_intel",
  requiredEnvVars: ["CONSTELLA_API_KEY"],
  capabilities: [{ queryType: "email", supportsWildcards: false, maxResults: 20 }],
  cost: { unit: "credit", estimatedCostPerQuery: 1, unknown: true },
  verificationNote:
    "Constella Intelligence (Hunter/DeepSight) nie oferuje samoobslugowego " +
    "dostepu API - sprzedaz wylacznie enterprise przez kontakt handlowy, bez " +
    "publicznej dokumentacji endpointow. Implementacja odlozona do czasu, gdy " +
    "uzytkownik uzyska dostep i oficjalna dokumentacje.",
});
