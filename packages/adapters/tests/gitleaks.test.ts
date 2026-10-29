import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import type { SafeSpawnResult } from "@unified-osint/core";
import { GitleaksAdapter } from "../src/gitleaks.js";

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

const REPO_URL = "https://github.com/example/repo";

describe("GitleaksAdapter", () => {
  it("klonuje, skanuje i zwraca znaleziony sekret jawnie w attrs (decyzja uzytkownika: bez maskowania)", async () => {
    const finding = {
      RuleID: "generic-api-key",
      Description: "Generic API Key",
      Secret: "SUPER-SECRET-VALUE-123",
      File: "config.js",
      Commit: "deadbeef",
      Link: `${REPO_URL}/blob/deadbeef/config.js`,
      Author: "Someone",
      Email: "someone@example.com",
      Date: "2024-01-01T00:00:00Z",
      Fingerprint: "fp-1",
      StartLine: 10,
    };

    const spawnFn = vi.fn(async (_binPath: string, args: string[]) => {
      if (args[0] === "clone") return fakeSpawnResult();
      const reportFile = argValue(args, "-r")!;
      await fs.writeFile(reportFile, JSON.stringify([finding]), "utf8");
      return fakeSpawnResult();
    });

    const adapter = new GitleaksAdapter({ binPath: "/fake/gitleaks", gitBinPath: "/fake/git", spawnFn });

    const records = [];
    for await (const record of adapter.search({ raw: REPO_URL, type: "url", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }

    expect(records).toHaveLength(1);
    const record = records[0]!;
    expect(record.attrs.secret).toBe("SUPER-SECRET-VALUE-123");
    expect((record.raw as typeof finding).Secret).toBe("SUPER-SECRET-VALUE-123");
    expect(record.sourceRecordId).toBe("fp-1");
  });

  it("nie skanuje, gdy klonowanie sie nie powiedzie", async () => {
    const spawnFn = vi.fn(async (_binPath: string, args: string[]) => {
      if (args[0] === "clone") return fakeSpawnResult({ exitCode: 1, stderr: "repository not found" });
      throw new Error("nie powinno dojsc do skanu");
    });
    const adapter = new GitleaksAdapter({ binPath: "/fake/gitleaks", gitBinPath: "/fake/git", spawnFn });

    const records = [];
    for await (const record of adapter.search({ raw: REPO_URL, type: "url", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }
    expect(records).toHaveLength(0);
  });

  it("odrzuca zapytania inne niz url oraz nie-https", () => {
    const adapter = new GitleaksAdapter({ binPath: "/fake/gitleaks", gitBinPath: "/fake/git" });
    expect(adapter.validateQuery({ raw: "test@example.com", type: "email", hasWildcards: false }).ok).toBe(false);
    expect(adapter.validateQuery({ raw: "http://github.com/x/y", type: "url", hasWildcards: false }).ok).toBe(false);
    expect(adapter.validateQuery({ raw: REPO_URL, type: "url", hasWildcards: false }).ok).toBe(true);
  });

  it("isConfigured() jest false, gdy binarka nie istnieje na dysku", () => {
    const adapter = new GitleaksAdapter({
      binPath: path.join(os.tmpdir(), "nie-istnieje-gitleaks.exe"),
      gitBinPath: "/fake/git",
    });
    expect(adapter.isConfigured()).toBe(false);
  });
});
