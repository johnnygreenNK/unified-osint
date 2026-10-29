import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { SafeSpawnResult } from "@unified-osint/core";
import { TruffleHogAdapter } from "../src/trufflehog.js";

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

const REPO_URL = "https://github.com/trufflesecurity/test_keys";

describe("TruffleHogAdapter", () => {
  it("parsuje ndjson, ignoruje linie bez DetectorName, maskuje sekret w attrs", async () => {
    const finding = {
      SourceMetadata: { Data: { Git: { commit: "abc123", file: "keys.txt", email: "a@example.com", repository: REPO_URL, timestamp: "2024-01-01T00:00:00Z", line: 3 } } },
      DetectorName: "AWS",
      Verified: false,
      Redacted: "AKIA****",
      Raw: "AKIAFULLSECRETVALUE",
      SecretParts: { key: "AKIAFULLSECRETVALUE" },
    };
    const stdout = `{"msg":"starting scan"}\n${JSON.stringify(finding)}\n`;
    const spawnFn = vi.fn(async () => fakeSpawnResult({ stdout }));
    const adapter = new TruffleHogAdapter({ binPath: "/fake/trufflehog", spawnFn });

    const records = [];
    for await (const record of adapter.search({ raw: REPO_URL, type: "url", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }

    expect(records).toHaveLength(1);
    const record = records[0]!;
    expect(record.attrs.detector).toBe("AWS");
    expect(record.attrs.redacted).toBe("AKIA****");
    expect(record.attrs.raw).toBeUndefined();
    expect(record.attrs.secretParts).toBeUndefined();
    expect((record.raw as typeof finding).Raw).toBe("AKIAFULLSECRETVALUE");
  });

  it("ignoruje uszkodzone/nie-JSON linie bez wywracania generatora", async () => {
    const spawnFn = vi.fn(async () => fakeSpawnResult({ stdout: "nie-json\n{bledny json\n" }));
    const adapter = new TruffleHogAdapter({ binPath: "/fake/trufflehog", spawnFn });

    const records = [];
    for await (const record of adapter.search({ raw: REPO_URL, type: "url", hasWildcards: false }, fakeContext())) {
      records.push(record);
    }
    expect(records).toHaveLength(0);
  });

  it("odrzuca zapytania inne niz url oraz nie-https", () => {
    const adapter = new TruffleHogAdapter({ binPath: "/fake/trufflehog" });
    expect(adapter.validateQuery({ raw: "test@example.com", type: "email", hasWildcards: false }).ok).toBe(false);
    expect(adapter.validateQuery({ raw: "http://github.com/x/y", type: "url", hasWildcards: false }).ok).toBe(false);
    expect(adapter.validateQuery({ raw: REPO_URL, type: "url", hasWildcards: false }).ok).toBe(true);
  });

  it("isConfigured() jest false, gdy binarka nie istnieje na dysku", () => {
    const adapter = new TruffleHogAdapter({ binPath: path.join(os.tmpdir(), "nie-istnieje-trufflehog.exe") });
    expect(adapter.isConfigured()).toBe(false);
  });
});
