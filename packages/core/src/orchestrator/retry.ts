/**
 * Klasyfikacja bledow i backoff z jitterem. Zasada: 401/403 NIGDY nie
 * ponawiamy (zly/wygasly klucz - ponawianie tylko dolozy kosztu i moze
 * przyspieszyc blokade konta u dostawcy). 429 ponawiamy, uwzgledniajac
 * Retry-After. 5xx i timeouty ponawiamy z backoffem. 4xx inne (400, 404)
 * NIE ponawiamy - to blad zapytania, nie przejsciowa awaria.
 */
export interface ClassifiedError {
  retryable: boolean;
  errorCode: string;
  suggestDisableAdapter: boolean;
  retryAfterMs?: number;
}

export function classifyHttpError(status: number, retryAfterHeader?: string | null): ClassifiedError {
  if (status === 401 || status === 403) {
    return { retryable: false, errorCode: `http_${status}`, suggestDisableAdapter: true };
  }
  if (status === 429) {
    const retryAfterMs = parseRetryAfter(retryAfterHeader);
    return { retryable: true, errorCode: "http_429", suggestDisableAdapter: false, retryAfterMs };
  }
  if (status >= 500) {
    return { retryable: true, errorCode: `http_${status}`, suggestDisableAdapter: false };
  }
  if (status >= 400) {
    return { retryable: false, errorCode: `http_${status}`, suggestDisableAdapter: false };
  }
  return { retryable: false, errorCode: `http_${status}`, suggestDisableAdapter: false };
}

export function classifyNetworkError(err: unknown): ClassifiedError {
  const message = err instanceof Error ? err.message : String(err);
  if (/timed? ?out|timeout/i.test(message)) {
    return { retryable: true, errorCode: "timeout", suggestDisableAdapter: false };
  }
  if (err instanceof Error && err.name === "SsrfBlockedError") {
    return { retryable: false, errorCode: "ssrf_blocked", suggestDisableAdapter: false };
  }
  return { retryable: true, errorCode: "network_error", suggestDisableAdapter: false };
}

function parseRetryAfter(header?: string | null): number | undefined {
  if (!header) return undefined;
  const seconds = Number(header);
  if (!Number.isNaN(seconds)) return seconds * 1000;
  const date = new Date(header).getTime();
  if (!Number.isNaN(date)) return Math.max(0, date - Date.now());
  return undefined;
}

export interface BackoffOptions {
  baseMs: number;
  maxMs: number;
  attempt: number; // 1-indexed
}

/** Wykladniczy backoff z pelnym jitterem (AWS-style): random(0, min(maxMs, baseMs * 2^attempt)). */
export function computeBackoffWithJitter({ baseMs, maxMs, attempt }: BackoffOptions): number {
  const exp = Math.min(maxMs, baseMs * 2 ** (attempt - 1));
  return Math.floor(Math.random() * exp);
}

export const MAX_RETRY_ATTEMPTS = 3;
