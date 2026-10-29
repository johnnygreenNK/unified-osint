import { spawn } from "node:child_process";
import fs from "node:fs";

/**
 * Wspolny runner dla adapterow opartych na natywnych narzedziach CLI
 * (Gitleaks, TruffleHog, Amass, Sherlock, Maigret, Holehe, theHarvester).
 * Zasady bezpieczenstwa:
 *  - argumenty ZAWSZE jako tablica (`args`), nigdy sklejany string + shell:true,
 *    aby wykluczyc command injection niezaleznie od tresci zapytania.
 *  - twardy timeout (SIGTERM) + respektowanie AbortSignal z SearchContext.
 *  - limit rozmiaru bufora stdout/stderr, aby zle zachowujacy sie proces nie
 *    zjadl calej pamieci workera.
 */

export interface SafeSpawnOptions {
  args: string[];
  cwd?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
  maxBufferBytes?: number;
  env?: NodeJS.ProcessEnv;
}

export interface SafeSpawnResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

const DEFAULT_TIMEOUT_MS = 60_000;
const DEFAULT_MAX_BUFFER_BYTES = 10 * 1024 * 1024; // 10 MiB

export class CliSpawnError extends Error {
  constructor(message: string, public readonly cause: Error) {
    super(message);
    this.name = "CliSpawnError";
  }
}

export function safeSpawn(binPath: string, options: SafeSpawnOptions): Promise<SafeSpawnResult> {
  return new Promise((resolve, reject) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(binPath, options.args, {
        cwd: options.cwd,
        env: options.env ?? process.env,
        windowsHide: true,
        shell: false,
      });
    } catch (err) {
      reject(new CliSpawnError(`Nie udalo sie uruchomic procesu ${binPath}`, err as Error));
      return;
    }

    let stdout = "";
    let stderr = "";
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;
    let settled = false;
    const maxBuffer = options.maxBufferBytes ?? DEFAULT_MAX_BUFFER_BYTES;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

    const onAbort = () => {
      child.kill("SIGTERM");
    };
    options.signal?.addEventListener("abort", onAbort, { once: true });

    const cleanup = () => {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
    };

    child.stdout?.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes <= maxBuffer) stdout += chunk.toString("utf8");
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.length;
      if (stderrBytes <= maxBuffer) stderr += chunk.toString("utf8");
    });

    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new CliSpawnError(`Blad procesu ${binPath}`, err));
    });

    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve({ exitCode: code, stdout, stderr, timedOut });
    });
  });
}

/** True, gdy plik binarny istnieje na dysku - uzywane przez isConfigured() adapterow CLI. */
export function binaryExists(binPath: string): boolean {
  try {
    return fs.statSync(binPath).isFile();
  } catch {
    return false;
  }
}
