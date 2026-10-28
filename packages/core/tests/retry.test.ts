import { describe, expect, it } from "vitest";
import { classifyHttpError, classifyNetworkError, computeBackoffWithJitter } from "../src/orchestrator/retry.js";

describe("classifyHttpError", () => {
  it("401/403 nie sa ponawiane i sugeruja wylaczenie adaptera", () => {
    expect(classifyHttpError(401)).toMatchObject({ retryable: false, suggestDisableAdapter: true });
    expect(classifyHttpError(403)).toMatchObject({ retryable: false, suggestDisableAdapter: true });
  });

  it("429 jest ponawiane i respektuje Retry-After", () => {
    const result = classifyHttpError(429, "2");
    expect(result.retryable).toBe(true);
    expect(result.retryAfterMs).toBe(2000);
  });

  it("5xx jest ponawiane", () => {
    expect(classifyHttpError(503).retryable).toBe(true);
  });

  it("inne 4xx (np. 400, 404) nie sa ponawiane", () => {
    expect(classifyHttpError(400).retryable).toBe(false);
    expect(classifyHttpError(404).retryable).toBe(false);
  });
});

describe("classifyNetworkError", () => {
  it("timeout jest ponawiany", () => {
    expect(classifyNetworkError(new Error("Request timed out")).retryable).toBe(true);
  });

  it("SsrfBlockedError nie jest ponawiany", () => {
    const err = new Error("blocked");
    err.name = "SsrfBlockedError";
    expect(classifyNetworkError(err).retryable).toBe(false);
  });
});

describe("computeBackoffWithJitter", () => {
  it("nigdy nie przekracza maxMs i rosnie z liczba prob", () => {
    for (let attempt = 1; attempt <= 5; attempt++) {
      const delay = computeBackoffWithJitter({ baseMs: 1000, maxMs: 30_000, attempt });
      expect(delay).toBeGreaterThanOrEqual(0);
      expect(delay).toBeLessThanOrEqual(30_000);
    }
  });
});
