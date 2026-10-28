const UNIT_SECONDS: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };

/** Parsuje proste duration-stringi uzywane w JWT_*_TTL (np. "15m", "30d") na sekundy, do cookie maxAge. */
export function durationToSeconds(value: string): number {
  const match = /^(\d+)(s|m|h|d)$/.exec(value.trim());
  if (!match) throw new Error(`Nieprawidlowy format czasu trwania: "${value}" (oczekiwano np. "15m", "30d")`);
  const [, amount, unit] = match;
  return Number(amount) * UNIT_SECONDS[unit!]!;
}
