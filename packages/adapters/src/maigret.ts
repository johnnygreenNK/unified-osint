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

interface MaigretSiteEntry {
  status?: { status?: string; url?: string; site_name?: string; ids?: Record<string, unknown> };
}

export interface MaigretAdapterConfig {
  binPath: string;
  spawnFn?: (args: string[], timeoutMs: number, signal: AbortSignal) => Promise<SafeSpawnResult>;
}

/**
 * Adapter Maigret - jak Sherlock, ale sprawdza wiecej serwisow i wydobywa
 * dodatkowe atrybuty z samych profili (np. lokalizacje, liczby followersow)
 * poprzez raport `-J simple` zapisywany do dedykowanego katalogu tymczasowego
 * (`--folderoutput`), zeby sciezka pliku byla deterministyczna.
 */
export class MaigretAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "maigret",
    name: "Maigret - wyszukiwanie username (rozszerzone)",
    category: "username_recon",
    requiredEnvVars: [],
    adapterVersion: "1.0.0",
    capabilities: [{ queryType: "username", supportsWildcards: false, maxResults: 500 }],
    cost: { unit: null, estimatedCostPerQuery: 0, unknown: false },
    setupInstructions: "Wymaga zainstalowanego Maigret (MAIGRET_BIN_PATH).",
  };

  constructor(private readonly config: MaigretAdapterConfig) {}

  isConfigured(): boolean {
    return binaryExists(this.config.binPath);
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (query.type !== "username") {
      return { ok: false, reason: "Adapter Maigret obsluguje tylko zapytania typu 'username'" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter Maigret nie wspiera wildcardow" };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const username = query.raw.trim();
    const outDir = path.join(os.tmpdir(), `maigret-${randomUUID()}`);
    const reportFile = path.join(outDir, `report_${username}_simple.json`);
    const run = this.config.spawnFn ?? ((args, timeoutMs, signal) => safeSpawn(this.config.binPath, { args, timeoutMs, signal }));

    try {
      const result = await run(
        [username, "-J", "simple", "--no-progressbar", "--no-color", "--folderoutput", outDir, "--timeout", "10"],
        context.timeoutMs,
        context.signal
      );
      if (context.signal.aborted) return;
      if (result.timedOut) {
        context.logger.warn("maigret_timed_out", { username });
      }

      const report = await readJsonIfExists(reportFile);
      for (const [siteName, entry] of Object.entries(report)) {
        if (context.signal.aborted) return;
        const status = (entry as MaigretSiteEntry).status;
        if (!status || status.status !== "Claimed" || !status.url) continue;
        try {
          yield this.normalizeResult({ username, siteName, status });
        } catch (err) {
          context.logger.warn("maigret_normalize_failed", { siteName, error: (err as Error).message });
        }
      }
    } finally {
      await fs.rm(outDir, { recursive: true, force: true }).catch(() => {});
    }
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const { username, siteName, status } = raw as {
      username: string;
      siteName: string;
      status: NonNullable<MaigretSiteEntry["status"]>;
    };
    const ids = status.ids ?? {};
    return {
      sourceRecordId: `${siteName}:${username}`,
      canonicalUrl: status.url ?? null,
      kind: "social_profile",
      title: `${status.site_name ?? siteName}: ${username}`,
      summary: `Profil znaleziony na ${status.site_name ?? siteName}`,
      attrs: { username, site: status.site_name ?? siteName, url: status.url, ...ids },
      observedAt: new Date().toISOString(),
      raw,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    if (!this.isConfigured()) {
      return { ok: false, errorCode: "not_configured", message: "MAIGRET_BIN_PATH nie wskazuje na istniejacy plik" };
    }
    const startedAt = Date.now();
    try {
      const controller = new AbortController();
      const result = await safeSpawn(this.config.binPath, { args: ["--version"], timeoutMs: 8000, signal: controller.signal });
      if (result.exitCode !== 0) {
        return { ok: false, errorCode: "maigret_healthcheck_failed", message: result.stderr.slice(0, 300) };
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "maigret_healthcheck_failed", message: (err as Error).message };
    }
  }
}

async function readJsonIfExists(filePath: string): Promise<Record<string, unknown>> {
  try {
    const content = await fs.readFile(filePath, "utf8");
    return JSON.parse(content) as Record<string, unknown>;
  } catch {
    return {};
  }
}
