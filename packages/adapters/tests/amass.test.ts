import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import type { SafeSpawnResult } from "@unified-osint/core";
import { AmassAdapter } from "../src/amass.js";

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

describe("AmassAdapter", () => {
  it("parsuje subdomeny z pliku wyjsciowego i deduplikuje", async () => {
    const spawnFn = vi.fn(async (_binPath: string, args: string[]) => {
      const outFile = argValue(args, "-o")!;
      await fs.writeFile(outFile, "sub1.example.com\nsub2.example.com\nsub1.example.com\n", "utf8");
      return fakeSpawnResult();
    });
    const adapter = new AmassAdapter({ binPath: "/fake/amass", timeoutMs: 60000, spawnFn });

    const records = [];
    for await (const record of adapter.search(
      { raw: "example.com", type: "domain", hasWildcards: false },
      fakeContext()
    )) {
      records.push(record);
    }

    expect(records).toHaveLength(2);
    expect(records.map((r) => r.attrs.subdomain).sort()).toEqual(["sub1.example.com", "sub2.example.com"]);
    expect(records[0]?.kind).toBe("subdomain");
  });

  it("nie wywraca generatora, gdy plik wyjsciowy nie istnieje (timeout/blad)", async () => {
    const spawnFn = vi.fn(async () => fakeSpawnResult({ exitCode: 1, timedOut: true }));
    const adapter = new AmassAdapter({ binPath: "/fake/amass", timeoutMs: 60000, spawnFn });

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
    const adapter = new AmassAdapter({ binPath: "/fake/amass", timeoutMs: 60000 });
    expect(adapter.validateQuery({ raw: "test@example.com", type: "email", hasWildcards: false }).ok).toBe(false);
    expect(adapter.validateQuery({ raw: "example.*", type: "domain", hasWildcards: true }).ok).toBe(false);
    expect(adapter.validateQuery({ raw: "example.com", type: "domain", hasWildcards: false }).ok).toBe(true);
  });

  it("isConfigured() jest false, gdy binarka nie istnieje na dysku", () => {
    const adapter = new AmassAdapter({ binPath: path.join(os.tmpdir(), "nie-istnieje-amass.exe"), timeoutMs: 60000 });
    expect(adapter.isConfigured()).toBe(false);
  });
});
