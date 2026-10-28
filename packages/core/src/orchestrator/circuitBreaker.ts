/**
 * Prosty circuit breaker w pamieci procesu, per source_id.
 * CLOSED -> (N kolejnych bledow) -> OPEN -> (po cooldown) -> HALF_OPEN
 * -> (1 sukces) -> CLOSED, (1 blad) -> OPEN.
 *
 * To jest pierwsza linia obrony w ramach jednego procesu workera. Trwaly
 * status adaptera (disabled/error) jest osobno utrwalany w tabeli `sources`
 * i to on jest wiazaca prawda dla UI oraz dla innych instancji workera.
 */
type CircuitState = "closed" | "open" | "half_open";

interface CircuitEntry {
  state: CircuitState;
  consecutiveFailures: number;
  openedAt: number | null;
}

export interface CircuitBreakerOptions {
  failureThreshold: number;
  cooldownMs: number;
}

export class CircuitBreaker {
  private readonly entries = new Map<string, CircuitEntry>();

  constructor(private readonly options: CircuitBreakerOptions = { failureThreshold: 5, cooldownMs: 60_000 }) {}

  canAttempt(sourceId: string): boolean {
    const entry = this.getEntry(sourceId);
    if (entry.state === "closed") return true;
    if (entry.state === "half_open") return true;
    // state === "open"
    if (entry.openedAt !== null && Date.now() - entry.openedAt >= this.options.cooldownMs) {
      entry.state = "half_open";
      return true;
    }
    return false;
  }

  recordSuccess(sourceId: string): void {
    const entry = this.getEntry(sourceId);
    entry.state = "closed";
    entry.consecutiveFailures = 0;
    entry.openedAt = null;
  }

  recordFailure(sourceId: string): void {
    const entry = this.getEntry(sourceId);
    entry.consecutiveFailures += 1;
    if (entry.state === "half_open") {
      entry.state = "open";
      entry.openedAt = Date.now();
      return;
    }
    if (entry.consecutiveFailures >= this.options.failureThreshold) {
      entry.state = "open";
      entry.openedAt = Date.now();
    }
  }

  getState(sourceId: string): CircuitState {
    return this.getEntry(sourceId).state;
  }

  private getEntry(sourceId: string): CircuitEntry {
    let entry = this.entries.get(sourceId);
    if (!entry) {
      entry = { state: "closed", consecutiveFailures: 0, openedAt: null };
      this.entries.set(sourceId, entry);
    }
    return entry;
  }
}
