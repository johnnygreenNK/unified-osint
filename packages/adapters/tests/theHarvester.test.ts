import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import type { SafeSpawnResult } from "@unified-osint/core";
import { TheHarvesterAdapter } from "../src/theHarvester.js";

function fakeContext(timeoutMs = 60000) {
  return {
    searchId: "s1",
    userId: "u1",
    userRole: "analyst" as const,
    correlationId: "c1",
    signal: new AbortController().signal,
    timeoutMs,
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
}

function fakeSpawnResult(overrides: Partial<SafeSpawnResult> = {}): SafeSpawnResult {
  return { exitCode: 0, stdout: "", stderr: "", timedOut: false, ...overrides };
}

describe("TheHarvesterAdapter", () => {
  it("parsuje out.json, mapuje pola na kind i deduplikuje", async () => {
    const report = {
      hosts: ["sub1.example.com", "sub1.example.com"],
      emails: ["a@example.com"],
      ips: ["1.2.3.4"],
      vhosts: ["sub2.example.com"],
      interesting_urls: ["https://example.com/admin"],
      asns: ["AS1234"],
    };

    const spawnFn = vi.fn(async (_args: string[], cwd: string) => {
      await fs.writeFile(path.join(cwd, "out.json"), JSON.stringify(report), "utf8");
      return fakeSpawnResult();
    });

    const adapter = new TheHarvesterAdapter({ binPath: "/fake/theHarvester", spawnFn });

    const records = [];
    for await (const record of adapter.search(
      { raw: "example.com", type: "domain", hasWildcards: false },
      fakeContext()
    )) {
      records.push(record);
    }

    expect(records).toHaveLength(6);
    const kinds = records.map((r) => r.kind).sort();
    expect(kinds).toEqual(["asn", "email_found", "interesting_url", "ip_found", "subdomain", "subdomain"].sort());
  });

  it("nie wywraca generatora, gdy out.json nie zostal utworzony", async () => {
    const spawnFn = vi.fn(async () => fakeSpawnResult({ exitCode: 1 }));
    const adapter = new TheHarvesterAdapter({ binPath: "/fake/theHarvester", spawnFn });

    const records = [];
    for await (const record of adapter.search(
      { raw: "example.com", type: "domain", hasWildcards: false },
      fakeContext()
    )) {
      records.push(record);
    }
    expect(records).toHaveLength(0);
  });

  it("odrzuca zapytania inne niz domain oraz z wildcardami", () => {
    const adapter = new TheHarvesterAdapter({ binPath: "/fake/theHarvester" });
    expect(adapter.validateQuery({ raw: "test@example.com", type: "email", hasWildcards: false }).ok).toBe(false);
    expect(adapter.validateQuery({ raw: "example.*", type: "domain", hasWildcards: true }).ok).toBe(false);
    expect(adapter.validateQuery({ raw: "example.com", type: "domain", hasWildcards: false }).ok).toBe(true);
  });

  it("isConfigured() jest false, gdy binarka nie istnieje na dysku", () => {
    const adapter = new TheHarvesterAdapter({ binPath: path.join(os.tmpdir(), "nie-istnieje-theharvester.exe") });
    expect(adapter.isConfigured()).toBe(false);
  });
});
