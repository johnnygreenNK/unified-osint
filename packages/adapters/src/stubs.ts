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
