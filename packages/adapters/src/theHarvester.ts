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

interface TheHarvesterReport {
  hosts?: string[];
  emails?: string[];
  ips?: string[];
  vhosts?: string[];
  interesting_urls?: string[];
  asns?: string[];
}

const ARRAY_KIND: Record<keyof Omit<TheHarvesterReport, never>, string> = {
  hosts: "subdomain",
  emails: "email_found",
  ips: "ip_found",
  vhosts: "subdomain",
  interesting_urls: "interesting_url",
  asns: "asn",
};

export interface TheHarvesterAdapterConfig {
  binPath: string;
  spawnFn?: (args: string[], cwd: string, timeoutMs: number, signal: AbortSignal) => Promise<SafeSpawnResult>;
}

/**
 * Adapter theHarvester - zbiera hosty/subdomeny/e-maile/IP dla domeny z
 * pasywnych zrodel (`-b all`; zrodla wymagajace klucza API po prostu nie
 * zwroca nic bez niego - `-q` ucisza tylko ostrzezenia o brakujacych kluczach,
 * nie jest to blad). Wynik parsowany z pliku JSON (`-f`), ktorego dokladny
 * ksztalt (hosts/emails/ips/vhosts/interesting_urls/asns) pochodzi z kodu
 * theHarvester - pola wystepuja tylko, gdy znaleziono cokolwiek danego typu.
 */
export class TheHarvesterAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "theharvester",
    name: "theHarvester - pasywny zbior hostow/e-maili dla domeny",
    category: "dns_infra",
    requiredEnvVars: [],
    adapterVersion: "1.0.0",
    capabilities: [{ queryType: "domain", supportsWildcards: false, maxResults: 500 }],
    cost: { unit: null, estimatedCostPerQuery: 0, unknown: false },
    setupInstructions: "Wymaga zainstalowanego theHarvester (THEHARVESTER_BIN_PATH).",
  };

  constructor(private readonly config: TheHarvesterAdapterConfig) {}

  isConfigured(): boolean {
    return binaryExists(this.config.binPath);
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (query.type !== "domain") {
      return { ok: false, reason: "Adapter theHarvester obsluguje tylko zapytania typu 'domain'" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter theHarvester nie wspiera wildcardow" };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const domain = query.raw.trim().toLowerCase();
    const workDir = path.join(os.tmpdir(), `theharvester-${randomUUID()}`);
    await fs.mkdir(workDir, { recursive: true });
    const outBase = "out";
    const jsonFile = path.join(workDir, `${outBase}.json`);

    const run = this.config.spawnFn ?? ((args, cwd, timeoutMs, signal) => safeSpawn(this.config.binPath, { args, cwd, timeoutMs, signal }));

    try {
      const result = await run(["-d", domain, "-b", "all", "-f", outBase, "-q"], workDir, context.timeoutMs, context.signal);
      if (context.signal.aborted) return;
      if (result.timedOut) {
        context.logger.warn("theharvester_timed_out", { domain });
      }

      const report = await readJsonIfExists(jsonFile);
      const seen = new Set<string>();
      for (const key of Object.keys(ARRAY_KIND) as (keyof TheHarvesterReport)[]) {
        const values = report[key];
        if (!Array.isArray(values)) continue;
        for (const value of values) {
          if (context.signal.aborted) return;
          if (typeof value !== "string" || !value.trim()) continue;
          const dedupeKey = `${key}:${value}`;
          if (seen.has(dedupeKey)) continue;
          seen.add(dedupeKey);
          yield this.normalizeResult({ domain, field: key, value, kind: ARRAY_KIND[key] });
        }
      }
    } finally {
      await fs.rm(workDir, { recursive: true, force: true }).catch(() => {});
    }
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const { domain, field, value, kind } = raw as { domain: string; field: string; value: string; kind: string };
    return {
      sourceRecordId: `${field}:${value}`,
      canonicalUrl: null,
      kind,
      title: value,
      summary: `${field} znaleziony dla ${domain}`,
      attrs: { domain, field, value },
      observedAt: new Date().toISOString(),
      raw,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    if (!this.isConfigured()) {
      return { ok: false, errorCode: "not_configured", message: "THEHARVESTER_BIN_PATH nie wskazuje na istniejacy plik" };
    }
    const startedAt = Date.now();
    try {
      const controller = new AbortController();
      const result = await safeSpawn(this.config.binPath, { args: ["--help"], timeoutMs: 8000, signal: controller.signal });
      if (result.exitCode !== 0) {
        return { ok: false, errorCode: "theharvester_healthcheck_failed", message: result.stderr.slice(0, 300) };
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "theharvester_healthcheck_failed", message: (err as Error).message };
    }
  }
}

async function readJsonIfExists(filePath: string): Promise<TheHarvesterReport> {
  try {
    const content = await fs.readFile(filePath, "utf8");
    return JSON.parse(content) as TheHarvesterReport;
  } catch {
    return {};
  }
}
