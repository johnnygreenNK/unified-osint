import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { randomUUID } from "node:crypto";
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

export interface AmassAdapterConfig {
  binPath: string;
  timeoutMs: number;
  /** Wstrzykiwalne dla testow. */
  spawnFn?: (binPath: string, args: string[], timeoutMs: number, signal: AbortSignal) => Promise<SafeSpawnResult>;
}

/**
 * Adapter Amass (OWASP) - pasywne wyliczanie subdomen dla domeny.
 *
 * Swiadomie BEZ flag `-active`/`-brute`: wylacznie pasywne zrodla (CT logs,
 * wyszukiwarki, archiwa) - zero zapytan bezposrednio do infrastruktury celu,
 * co jest zgodne z profilem bezpieczenstwa tego narzedzia (brak aktywnego
 * skanowania bez wyraznej zgody wlasciciela domeny).
 */
export class AmassAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "amass",
    name: "Amass (OWASP) - pasywne subdomeny",
    category: "dns_infra",
    requiredEnvVars: [],
    adapterVersion: "1.0.0",
    capabilities: [{ queryType: "domain", supportsWildcards: false, maxResults: 500 }],
    cost: { unit: null, estimatedCostPerQuery: 0, unknown: false },
    setupInstructions:
      "Wymaga zainstalowanego binarium Amass (AMASS_BIN_PATH). Dziala wylacznie w trybie pasywnym.",
  };

  constructor(private readonly config: AmassAdapterConfig) {}

  isConfigured(): boolean {
    return binaryExists(this.config.binPath);
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (query.type !== "domain") {
      return { ok: false, reason: "Adapter Amass obsluguje tylko zapytania typu 'domain'" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter Amass nie wspiera wildcardow - podaj dokladna domene" };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const domain = query.raw.trim().toLowerCase();
    const outFile = path.join(os.tmpdir(), `amass-${randomUUID()}.txt`);
    const timeoutMinutes = Math.max(1, Math.ceil(context.timeoutMs / 60_000));

    try {
      const run = this.config.spawnFn ?? defaultSpawn;
      const result = await run(
        this.config.binPath,
        ["enum", "-d", domain, "-o", outFile, "-timeout", String(timeoutMinutes), "-silent"],
        context.timeoutMs,
        context.signal
      );

      if (context.signal.aborted) return;

      if (result.timedOut) {
        context.logger.warn("amass_timed_out", { domain });
      } else if (result.exitCode !== 0) {
        context.logger.warn("amass_nonzero_exit", { domain, exitCode: result.exitCode, stderr: result.stderr.slice(0, 500) });
      }

      const lines = await readLinesIfExists(outFile);
      const seen = new Set<string>();
      for (const line of lines) {
        if (context.signal.aborted) return;
        const subdomain = line.trim().toLowerCase();
        if (!subdomain || seen.has(subdomain)) continue;
        seen.add(subdomain);
        yield this.normalizeResult({ domain, subdomain });
      }
    } finally {
      await fs.rm(outFile, { force: true }).catch(() => {});
    }
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const { domain, subdomain } = raw as { domain: string; subdomain: string };
    return {
      sourceRecordId: subdomain,
      canonicalUrl: null,
      kind: "subdomain",
      title: subdomain,
      summary: `Subdomena znaleziona pasywnie dla ${domain}`,
      attrs: { domain, subdomain },
      observedAt: new Date().toISOString(),
      raw,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    if (!this.isConfigured()) {
      return { ok: false, errorCode: "not_configured", message: "AMASS_BIN_PATH nie wskazuje na istniejacy plik" };
    }
    const startedAt = Date.now();
    try {
      const run = this.config.spawnFn ?? defaultSpawn;
      const controller = new AbortController();
      const result = await run(this.config.binPath, ["-version"], 5000, controller.signal);
      if (result.exitCode !== 0) {
        return { ok: false, errorCode: "amass_healthcheck_failed", message: result.stderr.slice(0, 300) };
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "amass_healthcheck_failed", message: (err as Error).message };
    }
  }
}

async function defaultSpawn(
  binPath: string,
  args: string[],
  timeoutMs: number,
  signal: AbortSignal
): Promise<SafeSpawnResult> {
  return safeSpawn(binPath, { args, timeoutMs, signal });
}

async function readLinesIfExists(filePath: string): Promise<string[]> {
  try {
    const content = await fs.readFile(filePath, "utf8");
    return content.split(/\r?\n/).filter(Boolean);
  } catch {
    return [];
  }
}
