import pino from "pino";

/**
 * Pola, ktore NIGDY nie moga trafic do logow w postaci jawnej.
 * pino.redact zastepuje je literalem "[REDACTED]" na kazdym poziomie zagniezdzenia.
 */
const REDACT_PATHS = [
  "*.password",
  "*.apiKey",
  "*.api_key",
  "*.token",
  "*.accessToken",
  "*.refreshToken",
  "*.authorization",
  "*.Authorization",
  "*.secret",
  "*.jwt",
  "*.SNUSBASE_API_KEY",
  "*.INTELX_API_KEY",
  "*.EPIEOS_API_KEY",
  "*.TELEGRAM_BOT_TOKEN",
  "headers.authorization",
  "headers.cookie",
];

export function createLogger(name: string, level: string = process.env.LOG_LEVEL ?? "info") {
  return pino({
    name,
    level,
    redact: { paths: REDACT_PATHS, censor: "[REDACTED]" },
    formatters: {
      level(label) {
        return { level: label };
      },
    },
  });
}

export type Logger = ReturnType<typeof createLogger>;
