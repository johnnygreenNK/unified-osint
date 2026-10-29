import type {
  AdapterDescriptor,
  AdapterRecord,
  HealthCheckResult,
  QueryValidation,
  SearchContext,
  SearchQuery,
  SourceAdapter,
  SourceCapability,
} from "@unified-osint/core";
import { safeSpawn, binaryExists, type SafeSpawnResult } from "@unified-osint/core";

export interface HoleheAdapterConfig {
  binPath: string;
  spawnFn?: (args: string[], timeoutMs: number, signal: AbortSignal) => Promise<SafeSpawnResult>;
}

const USED_LINE = /^\[\+\]\s+(\S+)/;

/**
 * Adapter Holehe - sprawdza, na ktorych serwisach dany e-mail jest
 * zarejestrowany (przez formularze "zapomnialem hasla"/rejestracji).
 *
 * UWAGA (decyzja uzytkownika, podjeta swiadomie z pelna znajomoscia ryzyka):
 * Holehe dziala wysylajac realne zadania do formularzy logowania/rejestracji
 * zewnetrznych serwisow, co u niektorych dostawcow moze naruszac ToS i grozi
 * np. tymczasowym zablokowaniem adresu IP. Uzytkownik zdecydowal sie
 * uwzglednic to narzedzie mimo tego ryzyka. Adapter NIE ogranicza
 * funkcjonalnosci (nie wymusza -NP/no-password-recovery), bo ograniczenie
 * tego akurat mechanizmu bylo wprost odrzucone przez uzytkownika.
 */
export class HoleheAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "holehe",
    name: "Holehe - rejestracja e-mail na serwisach (ryzyko ToS)",
    category: "username_recon",
    requiredEnvVars: [],
    adapterVersion: "1.0.0",
    capabilities: [{ queryType: "email", supportsWildcards: false, maxResults: 150 }],
    cost: { unit: null, estimatedCostPerQuery: 0, unknown: false },
    setupInstructions:
      "Wymaga zainstalowanego Holehe (HOLEHE_BIN_PATH). Ryzyko ToS/abuse zaakceptowane przez uzytkownika.",
  };

  constructor(private readonly config: HoleheAdapterConfig) {}

  isConfigured(): boolean {
    return binaryExists(this.config.binPath);
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (query.type !== "email") {
      return { ok: false, reason: "Adapter Holehe obsluguje tylko zapytania typu 'email'" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter Holehe nie wspiera wildcardow" };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const email = query.raw.trim();
    const run = this.config.spawnFn ?? ((args, timeoutMs, signal) => safeSpawn(this.config.binPath, { args, timeoutMs, signal }));
    const result = await run([email, "--only-used", "--no-color", "--no-clear"], context.timeoutMs, context.signal);

    if (context.signal.aborted) return;
    if (result.timedOut) {
      context.logger.warn("holehe_timed_out", { email });
    }

    for (const line of result.stdout.split(/\r?\n/)) {
      if (context.signal.aborted) return;
      const match = USED_LINE.exec(line.trim());
      const site = match?.[1]?.trim();
      // Holehe wypisuje na koniec linie legendy, np. "[+] Email used, [-] Email
      // not used, [x] Rate limit, [!] Error" - zaczyna sie od tego samego "[+] "
      // co wynik, ale "Email" to nie nazwa serwisu, wiec trzeba ja odrzucic.
      if (!site || site.toLowerCase() === "email") continue;
      yield this.normalizeResult({ email, site });
    }
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const { email, site } = raw as { email: string; site: string };
    return {
      sourceRecordId: `${site}:${email}`,
      canonicalUrl: null,
      kind: "email_registration",
      title: `Zarejestrowany na ${site}`,
      summary: `E-mail ${email} jest uzywany na ${site}`,
      attrs: { email, site },
      observedAt: new Date().toISOString(),
      raw,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    if (!this.isConfigured()) {
      return { ok: false, errorCode: "not_configured", message: "HOLEHE_BIN_PATH nie wskazuje na istniejacy plik" };
    }
    const startedAt = Date.now();
    try {
      const controller = new AbortController();
      const result = await safeSpawn(this.config.binPath, { args: ["--help"], timeoutMs: 5000, signal: controller.signal });
      if (result.exitCode !== 0) {
        return { ok: false, errorCode: "holehe_healthcheck_failed", message: result.stderr.slice(0, 300) };
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "holehe_healthcheck_failed", message: (err as Error).message };
    }
  }
}
