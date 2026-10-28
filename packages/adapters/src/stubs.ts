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

export const snusbaseStub: SourceAdapter = createNotConfiguredStub({
  id: "snusbase",
  name: "Snusbase (wyszukiwarka wyciekow danych)",
  category: "breach_data",
  requiredEnvVars: ["SNUSBASE_API_KEY"],
  capabilities: [
    { queryType: "email", supportsWildcards: false, maxResults: 20 },
    { queryType: "username", supportsWildcards: false, maxResults: 20 },
  ],
  cost: { unit: "credit", estimatedCostPerQuery: 1, unknown: true },
  verificationNote:
    "Endpointy, naglowki autoryzacji, dokladny format zapytan i limity API Snusbase " +
    "wymagaja weryfikacji w oficjalnej dokumentacji dostawcy przed implementacja " +
    "(beta.snusbase.com to panel UI, nie dokumentacja API). Po implementacji: " +
    "zakres ograniczony do sprawdzenia obecnosci email/username w wycieku (bez " +
    "masowego/wildcard wydobywania hasel), dostep tylko dla rol analyst/admin, " +
    "maskowanie hashy/hasel w UI/SSE/Telegramie domyslnie, kazde odslonie w audit_logs.",
});

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
    "Integracja ograniczona wylacznie do oficjalnego API Epieos (bez scrapowania " +
    "UI wbrew ToS). Dokladne endpointy i format odpowiedzi do weryfikacji w " +
    "oficjalnej dokumentacji przed implementacja.",
});
