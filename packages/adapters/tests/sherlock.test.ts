import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { SafeSpawnResult } from "@unified-osint/core";
import { SherlockAdapter } from "../src/sherlock.js";

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

describe("SherlockAdapter", () => {
  it("parsuje linie '[+] Site: URL' i ignoruje pozostale", async () => {
    const stdout = [
      "[*] Checking username torvalds on:",
      "[+] GitHub: https://github.com/torvalds",
      "[+] Reddit: https://reddit.com/user/torvalds",
      "[-] SomeSite: Not Found!",
      "",
    ].join("\n");
    const spawnFn = vi.fn(async () => fakeSpawnResult({ stdout }));
    const adapter = new SherlockAdapter({ binPath: "/fake/sherlock", spawnFn });

    const records = [];
    for await (const record of adapter.search(
      { raw: "torvalds", type: "username", hasWildcards: false },
      fakeContext()
    )) {
      records.push(record);
    }

    expect(records).toHaveLength(2);
    expect(records[0]?.attrs.site).toBe("GitHub");
    expect(records[0]?.canonicalUrl).toBe("https://github.com/torvalds");
    expect(records[1]?.attrs.site).toBe("Reddit");
  });

  it("odrzuca zapytania inne niz username oraz z wildcardami", () => {
    const adapter = new SherlockAdapter({ binPath: "/fake/sherlock" });
    expect(adapter.validateQuery({ raw: "test@example.com", type: "email", hasWildcards: false }).ok).toBe(false);
    expect(adapter.validateQuery({ raw: "tor*", type: "username", hasWildcards: true }).ok).toBe(false);
    expect(adapter.validateQuery({ raw: "torvalds", type: "username", hasWildcards: false }).ok).toBe(true);
  });

  it("isConfigured() jest false, gdy binarka nie istnieje na dysku", () => {
    const adapter = new SherlockAdapter({ binPath: path.join(os.tmpdir(), "nie-istnieje-sherlock.exe") });
    expect(adapter.isConfigured()).toBe(false);
  });
});
