import net from "node:net";

/**
 * Sprawdza, czy adres IP (v4 lub v6) wskazuje na siec prywatna, loopback,
 * link-local (w tym metadane chmurowe 169.254.169.254), multicast lub inny
 * zakres zarezerwowany. Uzywane przez safeFetch do blokowania SSRF.
 *
 * Zakresy IPv4: RFC 1918, RFC 5735, RFC 3927 (link-local), RFC 6598 (CGNAT).
 * Zakresy IPv6: RFC 4193 (ULA), link-local fe80::/10, loopback ::1,
 * oraz zmapowane adresy IPv4 (::ffff:a.b.c.d) sprawdzane rekurencyjnie.
 */
export function isDisallowedIp(ip: string): boolean {
  const version = net.isIP(ip);
  if (version === 4) return isDisallowedIpv4(ip);
  if (version === 6) return isDisallowedIpv6(ip);
  // Nie da sie zaklasyfikowac -> traktuj jako niedozwolone (fail closed).
  return true;
}

function isDisallowedIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return true;
  }
  const [a, b] = parts as [number, number, number, number];

  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // RFC1918
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local, w tym 169.254.169.254 (cloud metadata)
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
  if (a === 192 && b === 168) return true; // RFC1918
  if (a === 192 && b === 0) return true; // IETF protocol assignments / benchmarking
  if (a === 100 && b >= 64 && b <= 127) return true; // RFC6598 CGNAT
  if (a >= 224) return true; // multicast + reserved (224-255)
  return false;
}

function isDisallowedIpv6(ip: string): boolean {
  const normalized = ip.toLowerCase();

  if (normalized === "::1") return true; // loopback
  if (normalized === "::") return true; // unspecified

  // IPv4-mapped (::ffff:a.b.c.d) i IPv4-compatible (::a.b.c.d) - sprawdz jako IPv4.
  const v4MappedMatch = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (v4MappedMatch) return isDisallowedIpv4(v4MappedMatch[1]!);

  // Link-local fe80::/10
  if (/^fe[89ab][0-9a-f]:/.test(normalized)) return true;

  // Unique local fc00::/7 (fc00:: - fdff::)
  if (/^f[cd][0-9a-f]{2}:/.test(normalized)) return true;

  // Multicast ff00::/8
  if (normalized.startsWith("ff")) return true;

  return false;
}

export function isAllowedProtocol(protocol: string): boolean {
  return protocol === "http:" || protocol === "https:";
}
