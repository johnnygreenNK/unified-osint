import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import type { SafeSpawnResult } from "@unified-osint/core";
import { MaigretAdapter } from "../src/maigret.js";

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

function argValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx === -1 ? undefined : args[idx + 1];
}

function fakeSpawnResult(overrides: Partial<SafeSpawnResult> = {}): SafeSpawnResult {
  return { exitCode: 0, stdout: "", stderr: "", timedOut: false, ...overrides };
}

describe("MaigretAdapter", () => {
  it("parsuje raport JSON i zwraca tylko wpisy ze statusem 'Claimed'", async () => {
    const username = "testuser";
    const report = {
      GitHub: {
        status: { status: "Claimed", url: "https://github.com/testuser", site_name: "GitHub", ids: { fullName: "Test User" } },
      },
      SomeSite: { status: { status: "NotFound" } },
    };

    const spawnFn = vi.fn(async (args: string[]) => {
      const outDir = argValue(args, "--folderoutput")!;
      await fs.mkdir(outDir, { recursive: true });
      await fs.writeFile(path.join(outDir, `report_${username}_simple.json`), JSON.stringify(report), "utf8");
      return fakeSpawnResult();
    });

    const adapter = new MaigretAdapter({ binPath: "/fake/maigret", spawnFn });

    const records = [];
    for await (const record of adapter.search(
      { raw: username, type: "username", hasWildcards: false },
      fakeContext()
    )) {
      records.push(record);
    }

    expect(records).toHaveLength(1);
    expect(records[0]?.attrs.site).toBe("GitHub");
    expect(records[0]?.attrs.fullName).toBe("Test User");
    expect(records[0]?.canonicalUrl).toBe("https://github.com/testuser");
  });

  it("nie wywraca generatora, gdy raport nie zostal utworzony", async () => {
    const spawnFn = vi.fn(async () => fakeSpawnResult({ exitCode: 1, timedOut: true }));
    const adapter = new MaigretAdapter({ binPath: "/fake/maigret", spawnFn });

    const records = [];
    for await (const record of adapter.search(
      { raw: "nikt", type: "username", hasWildcards: false },
      fakeContext()
    )) {
      records.push(record);
    }
    expect(records).toHaveLength(0);
  });

  it("odrzuca zapytania inne niz username oraz z wildcardami", () => {
    const adapter = new MaigretAdapter({ binPath: "/fake/maigret" });
    expect(adapter.validateQuery({ raw: "test@example.com", type: "email", hasWildcards: false }).ok).toBe(false);
    expect(adapter.validateQuery({ raw: "test*", type: "username", hasWildcards: true }).ok).toBe(false);
    expect(adapter.validateQuery({ raw: "testuser", type: "username", hasWildcards: false }).ok).toBe(true);
  });

  it("isConfigured() jest false, gdy binarka nie istnieje na dysku", () => {
    const adapter = new MaigretAdapter({ binPath: path.join(os.tmpdir(), "nie-istnieje-maigret.exe") });
    expect(adapter.isConfigured()).toBe(false);
  });
});
