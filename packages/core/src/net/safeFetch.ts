import http from "node:http";
import https from "node:https";
import dns from "node:dns/promises";
import type { LookupAddress } from "node:dns";
import { isAllowedProtocol, isDisallowedIp } from "./ipGuard.js";

export class SsrfBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfBlockedError";
  }
}

export interface SafeFetchOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string | Buffer;
  timeoutMs?: number;
  maxRedirects?: number;
  maxBodyBytes?: number;
  signal?: AbortSignal;
  /**
   * TYLKO do testow lokalnych (np. przeciwko kontenerowi testowemu w tej
   * samej siecu Docker). Nigdy nie wlaczaj w produkcji - wylacza ochrone SSRF.
   */
  allowPrivateNetworks?: boolean;
}

export interface SafeFetchResult {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
  finalUrl: string;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_REDIRECTS = 5;
const DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024; // 5 MiB

/**
 * Pobiera URL z ochrona przed SSRF:
 *  - dopuszcza wylacznie http/https,
 *  - rozwiazuje DNS raz i PINUJE wynikowy adres IP na caly czas polaczenia
 *    (ochrona przed DNS rebinding - connect() nie rozwiazuje hosta ponownie),
 *  - odrzuca adresy loopback / prywatne / link-local / metadane chmurowe,
 *  - obsluguje przekierowania recznie, walidujac KAZDY nowy adres tak samo,
 *  - wymusza limit czasu i limit rozmiaru odpowiedzi.
 *
 * Uzywaj tej funkcji we wszystkich adapterach, ktore pobieraja URL podany
 * (bezposrednio lub pochodnie) przez uzytkownika albo przez wynik z innego,
 * niezaufanego zrodla.
 */
export async function safeFetch(
  rawUrl: string,
  options: SafeFetchOptions = {}
): Promise<SafeFetchResult> {
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  let currentUrl = rawUrl;

  for (let redirectCount = 0; redirectCount <= maxRedirects; redirectCount++) {
    const result = await singleRequest(currentUrl, options);
    if (result.kind === "redirect") {
      currentUrl = result.location;
      continue;
    }
    return result.value;
  }

  throw new SsrfBlockedError(`Przekroczono maksymalna liczbe przekierowan (${maxRedirects}) dla ${rawUrl}`);
}

type SingleRequestOutcome =
  | { kind: "redirect"; location: string }
  | { kind: "final"; value: SafeFetchResult };

async function singleRequest(
  rawUrl: string,
  options: SafeFetchOptions
): Promise<SingleRequestOutcome> {
  const url = new URL(rawUrl);

  if (!isAllowedProtocol(url.protocol)) {
    throw new SsrfBlockedError(`Niedozwolony protokol: ${url.protocol} (dozwolone: http, https)`);
  }

  const pinnedAddress = await resolveAndValidate(url.hostname, options.allowPrivateNetworks ?? false);

  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const transport = url.protocol === "https:" ? https : http;

  return new Promise<SingleRequestOutcome>((resolve, reject) => {
    const controller = new AbortController();
    const onExternalAbort = () => controller.abort();
    options.signal?.addEventListener("abort", onExternalAbort, { once: true });

    const timer = setTimeout(() => {
      controller.abort();
    }, timeoutMs);

    const req = transport.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname + url.search,
        method: options.method ?? "GET",
        headers: {
          "User-Agent": "UnifiedOSINT-Adapter/1.0",
          ...options.headers,
        },
        signal: controller.signal,
        // Pinowanie adresu: niezaleznie od hostname, polaczenie TCP idzie na
        // adres rozwiazany i zwalidowany wyzej - zero ponownego DNS przy connect.
        lookup: (_hostname, lookupOptions, callback) => {
          if (typeof lookupOptions === "function") {
            // Node moze wywolac lookup(hostname, callback) bez opcji.
            (lookupOptions as unknown as (err: Error | null, address: string, family: number) => void)(
              null,
              pinnedAddress.address,
              pinnedAddress.family
            );
            return;
          }
          // Od Node 20 `autoSelectFamily` (happy eyeballs) jest wlaczone
          // domyslnie i Socket.connect woła lookup z `{ all: true }`,
          // oczekujac callback(err, addresses[]) zamiast callback(err, address,
          // family) - bez tej rozdzielnej sciezki kazde polaczenie https przez
          // safeFetch rzuca wewnetrzny TypeError "Invalid IP address: undefined".
          if (lookupOptions.all) {
            callback(null, [{ address: pinnedAddress.address, family: pinnedAddress.family }] as never);
            return;
          }
          callback(null, pinnedAddress.address, pinnedAddress.family);
        },
      },
      (res) => {
        const status = res.statusCode ?? 0;

        if (status >= 300 && status < 400 && res.headers.location) {
          res.resume(); // odrzuc body przekierowania
          clearTimeout(timer);
          options.signal?.removeEventListener("abort", onExternalAbort);
          const nextUrl = new URL(res.headers.location, url).toString();
          resolve({ kind: "redirect", location: nextUrl });
          return;
        }

        const chunks: Buffer[] = [];
        let totalBytes = 0;
        res.on("data", (chunk: Buffer) => {
          totalBytes += chunk.length;
          if (totalBytes > maxBodyBytes) {
            // Nie wywolujemy controller.abort() synchronicznie tutaj: ten sam
            // AbortSignal jest wewnetrznie podpiety przez Node do strumienia
            // `res` (ktory wlasnie jest w trakcie emitowania 'data'), a
            // synchroniczny abort w tym miejscu powoduje reentrantny
            // destroy() i nieprzechwytywalny wyjatek poza 'error' na res/req.
            // Odlozenie o jeden tick usuwa ta reentrancje.
            setImmediate(() => controller.abort());
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          clearTimeout(timer);
          options.signal?.removeEventListener("abort", onExternalAbort);
          if (totalBytes > maxBodyBytes) {
            reject(new SsrfBlockedError(`Odpowiedz przekroczyla limit rozmiaru (${maxBodyBytes} B): ${rawUrl}`));
            return;
          }
          resolve({
            kind: "final",
            value: {
              status,
              headers: res.headers,
              body: Buffer.concat(chunks),
              finalUrl: url.toString(),
            },
          });
        });
        res.on("error", (err) => {
          clearTimeout(timer);
          options.signal?.removeEventListener("abort", onExternalAbort);
          reject(err);
        });
      }
    );

    req.on("error", (err) => {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onExternalAbort);
      if (controller.signal.aborted) {
        reject(new Error(`Zadanie przekroczylo limit czasu (${timeoutMs} ms) lub zostalo anulowane: ${rawUrl}`));
        return;
      }
      reject(err);
    });

    if (options.body) req.write(options.body);
    req.end();
  });
}

async function resolveAndValidate(
  hostname: string,
  allowPrivateNetworks: boolean
): Promise<{ address: string; family: number }> {
  let addresses: LookupAddress[];
  try {
    addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch (err) {
    throw new SsrfBlockedError(`Nie udalo sie rozwiazac hosta ${hostname}: ${(err as Error).message}`);
  }

  if (addresses.length === 0) {
    throw new SsrfBlockedError(`Host ${hostname} nie rozwiazuje sie do zadnego adresu IP`);
  }

  if (!allowPrivateNetworks) {
    for (const { address } of addresses) {
      if (isDisallowedIp(address)) {
        throw new SsrfBlockedError(
          `Host ${hostname} rozwiazuje sie do niedozwolonego adresu ${address} (siec prywatna/loopback/link-local)`
        );
      }
    }
  }

  const chosen = addresses[0]!;
  return { address: chosen.address, family: chosen.family };
}
