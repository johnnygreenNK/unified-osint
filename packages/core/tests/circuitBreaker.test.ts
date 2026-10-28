import { describe, expect, it, vi } from "vitest";
import { CircuitBreaker } from "../src/orchestrator/circuitBreaker.js";

describe("CircuitBreaker", () => {
  it("otwiera sie po przekroczeniu progu bledow i blokuje kolejne proby", () => {
    const cb = new CircuitBreaker({ failureThreshold: 3, cooldownMs: 60_000 });
    expect(cb.canAttempt("src-a")).toBe(true);
    cb.recordFailure("src-a");
    cb.recordFailure("src-a");
    expect(cb.canAttempt("src-a")).toBe(true); // jeszcze pod progiem
    cb.recordFailure("src-a");
    expect(cb.getState("src-a")).toBe("open");
    expect(cb.canAttempt("src-a")).toBe(false);
  });

  it("sukces resetuje licznik bledow", () => {
    const cb = new CircuitBreaker({ failureThreshold: 2, cooldownMs: 60_000 });
    cb.recordFailure("src-b");
    cb.recordSuccess("src-b");
    cb.recordFailure("src-b");
    expect(cb.getState("src-b")).toBe("closed");
  });

  it("przechodzi w half_open po cooldown i wraca do closed po sukcesie", () => {
    vi.useFakeTimers();
    const cb = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 1000 });
    cb.recordFailure("src-c");
    expect(cb.canAttempt("src-c")).toBe(false);

    vi.advanceTimersByTime(1500);
    expect(cb.canAttempt("src-c")).toBe(true);
    expect(cb.getState("src-c")).toBe("half_open");

    cb.recordSuccess("src-c");
    expect(cb.getState("src-c")).toBe("closed");
    vi.useRealTimers();
  });

  it("izoluje zrodla od siebie - awaria jednego nie blokuje drugiego", () => {
    const cb = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 60_000 });
    cb.recordFailure("src-x");
    expect(cb.canAttempt("src-x")).toBe(false);
    expect(cb.canAttempt("src-y")).toBe(true);
  });
});
