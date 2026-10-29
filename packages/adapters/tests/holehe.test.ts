import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { SafeSpawnResult } from "@unified-osint/core";
import { HoleheAdapter } from "../src/holehe.js";

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

describe("HoleheAdapter", () => {
  it("parsuje linie '[+] site' i ignoruje pozostale", async () => {
    const stdout = ["[+] gmail.com", "[-] somesite.com", "[x] errored.com", "[+] twitter.com", ""].join("\n");
    const spawnFn = vi.fn(async () => fakeSpawnResult({ stdout }));
    const adapter = new HoleheAdapter({ binPath: "/fake/holehe", spawnFn });

    const records = [];
    for await (const record of adapter.search(
      { raw: "test@example.com", type: "email", hasWildcards: false },
      fakeContext()
    )) {
      records.push(record);
    }

    expect(records).toHaveLength(2);
    expect(records.map((r) => r.attrs.site)).toEqual(["gmail.com", "twitter.com"]);
  });

  it("odrzuca zapytania inne niz email oraz z wildcardami", () => {
    const adapter = new HoleheAdapter({ binPath: "/fake/holehe" });
    expect(adapter.validateQuery({ raw: "torvalds", type: "username", hasWildcards: false }).ok).toBe(false);
    expect(adapter.validateQuery({ raw: "test*@example.com", type: "email", hasWildcards: true }).ok).toBe(false);
    expect(adapter.validateQuery({ raw: "test@example.com", type: "email", hasWildcards: false }).ok).toBe(true);
  });

  it("isConfigured() jest false, gdy binarka nie istnieje na dysku", () => {
    const adapter = new HoleheAdapter({ binPath: path.join(os.tmpdir(), "nie-istnieje-holehe.exe") });
    expect(adapter.isConfigured()).toBe(false);
  });
});
