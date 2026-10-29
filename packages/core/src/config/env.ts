import { z } from "zod";

/**
 * Pojedynczy, wspolny schemat walidacji zmiennych srodowiskowych.
 * Uzywany przez apps/api i apps/worker, aby nie rozjezdzaly sie definicje.
 *
 * Zasada: brak klucza do platnego API NIE jest bledem startu procesu -
 * adapter po prostu wejdzie w status `not_configured`. Bledem startu jest
 * brak czegokolwiek wymaganego do dzialania samej platformy (DB, sekrety JWT).
 */
const boolFromString = z
  .string()
  .optional()
  .transform((v) => v === "true" || v === "1");

export const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace"]).default("info"),

  DATABASE_URL: z.string().url().or(z.string().min(1)),

  JWT_ACCESS_SECRET: z.string().min(32, "JWT_ACCESS_SECRET musi miec co najmniej 32 znaki"),
  JWT_REFRESH_SECRET: z.string().min(32, "JWT_REFRESH_SECRET musi miec co najmniej 32 znaki"),
  JWT_ACCESS_TTL: z.string().default("15m"),
  JWT_REFRESH_TTL: z.string().default("30d"),
  AUTH_ARGON2_MEMORY_KB: z.coerce.number().int().positive().default(19456),

  API_HOST: z.string().default("0.0.0.0"),
  API_PORT: z.coerce.number().int().positive().default(4000),
  API_PUBLIC_URL: z.string().url().default("http://localhost:4000"),
  WEB_PUBLIC_URL: z.string().url().default("http://localhost:3000"),
  CORS_ALLOWED_ORIGINS: z
    .string()
    .default("http://localhost:3000")
    .transform((v) => v.split(",").map((s) => s.trim()).filter(Boolean)),

  WORKER_CONCURRENCY: z.coerce.number().int().positive().default(5),
  WORKER_PG_SCHEMA: z.string().default("pgboss"),

  MAX_SOURCES_PER_SEARCH: z.coerce.number().int().positive().default(8),
  MAX_CONCURRENT_SEARCHES_PER_USER: z.coerce.number().int().positive().default(2),
  DEFAULT_ADAPTER_TIMEOUT_MS: z.coerce.number().int().positive().default(15000),
  GLOBAL_SEARCH_BUDGET_PER_DAY: z.coerce.number().int().positive().default(200),

  ADAPTER_DEMO_ENABLED: boolFromString,
  ADAPTER_DNS_ENABLED: boolFromString,
  ADAPTER_RDAP_ENABLED: boolFromString,
  ADAPTER_CRTSH_ENABLED: boolFromString,
  ADAPTER_WAYBACK_ENABLED: boolFromString,

  SNUSBASE_API_KEY: z.string().optional().default(""),
  SNUSBASE_API_BASE_URL: z.string().url().default("https://api.snusbase.com"),

  EPIEOS_API_KEY: z.string().optional().default(""),
  EPIEOS_API_BASE_URL: z.string().url().default("https://api.epieos.com"),

  INTELX_API_KEY: z.string().optional().default(""),
  INTELX_API_BASE_URL: z.string().url().default("https://2.intelx.io"),

  HIBP_API_KEY: z.string().optional().default(""),
  HUNTER_API_KEY: z.string().optional().default(""),
  SHODAN_API_KEY: z.string().optional().default(""),
  CENSYS_API_ID: z.string().optional().default(""),
  CENSYS_API_SECRET: z.string().optional().default(""),
  VIRUSTOTAL_API_KEY: z.string().optional().default(""),
  GITHUB_TOKEN: z.string().optional().default(""),

  TELEGRAM_BOT_TOKEN: z.string().optional().default(""),
  TELEGRAM_WEBHOOK_SECRET: z.string().optional().default(""),
  TELEGRAM_WEBHOOK_URL: z.string().optional().default(""),

  OUTBOUND_HTTP_ALLOW_PRIVATE_NETWORKS: boolFromString,
  OUTBOUND_HTTP_TIMEOUT_MS: z.coerce.number().int().positive().default(10000),

  /**
   * Sciezki do binarek natywnych narzedzi CLI (Faza 3) - uruchamianych
   * lokalnie na Windows bez kontenerow (decyzja uzytkownika). Brak pliku pod
   * dana sciezka = adapter wchodzi w status `not_configured` (prawdziwy stan,
   * nie "wylaczony na sile"). Domyslne wartosci wskazuja miejsca, w ktorych
   * narzedzia zostaly faktycznie zainstalowane w tym srodowisku
   * (winget/pipx/go build) - nadpisywalne w .env, gdy ktos zainstaluje je
   * gdzie indziej lub doda do PATH.
   */
  CLI_ADAPTER_TIMEOUT_MS: z.coerce.number().int().positive().default(120000),
  GITLEAKS_BIN_PATH: z.string().default(
    "C:\\Users\\user\\AppData\\Local\\Microsoft\\WinGet\\Packages\\Gitleaks.Gitleaks_Microsoft.Winget.Source_8wekyb3d8bbwe\\gitleaks.exe"
  ),
  AMASS_BIN_PATH: z.string().default(
    "C:\\Users\\user\\AppData\\Local\\Microsoft\\WinGet\\Packages\\OWASP.Amass_Microsoft.Winget.Source_8wekyb3d8bbwe\\amass_Windows_amd64\\amass.exe"
  ),
  TRUFFLEHOG_BIN_PATH: z.string().default("C:\\Users\\user\\go\\bin\\trufflehog.exe"),
  SHERLOCK_BIN_PATH: z.string().default(
    "C:\\Users\\user\\Desktop\\osint\\.pytools\\sherlock\\Scripts\\sherlock.exe"
  ),
  MAIGRET_BIN_PATH: z.string().default(
    "C:\\Users\\user\\Desktop\\osint\\.pytools\\maigret\\Scripts\\maigret.exe"
  ),
  HOLEHE_BIN_PATH: z.string().default(
    "C:\\Users\\user\\Desktop\\osint\\.pytools\\holehe\\Scripts\\holehe.exe"
  ),
  THEHARVESTER_BIN_PATH: z.string().default(
    "C:\\Users\\user\\Desktop\\osint\\.pytools\\theHarvester\\Scripts\\theHarvester.exe"
  ),
  /** Git wymagany przez adapter Gitleaks (klonuje repo do tmp przed skanem) - zwykle na PATH. */
  GIT_BIN_PATH: z.string().default("git"),
});

export type Env = z.infer<typeof envSchema>;

let cached: Env | undefined;

/**
 * Parsuje process.env. Rzuca z czytelnym komunikatem, gdy brakuje
 * czegokolwiek wymaganego do samego startu procesu (nie integracji OSINT).
 */
export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  if (cached) return cached;
  const result = envSchema.safeParse(source);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    throw new Error(
      `Nieprawidlowa konfiguracja srodowiska (.env). Napraw nastepujace pola:\n${issues}`
    );
  }
  cached = result.data;
  return cached;
}

/** Tylko do testow - pozwala wyczyscic cache miedzy przypadkami testowymi. */
export function __resetEnvCacheForTests(): void {
  cached = undefined;
}
