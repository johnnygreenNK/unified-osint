/**
 * Formatowanie wynikow wyszukiwania na wiadomosci Telegram (HTML) - logika
 * wyciagania pol (email/haslo/data/nazwa wycieku) jest kopia breachDisplay()
 * z apps/web/src/app/dashboard/page.tsx, zeby panel web i bot pokazywaly
 * identyczne dane bez klikania w szczegoly.
 */
import { escapeHtml } from "./telegramClient.js";

export interface CanonicalResult {
  canonicalRecordId: string;
  sourceId: string;
  kind: string;
  title: string;
  sourceCount: number;
  attrs: Record<string, unknown>;
}

const KIND_LABELS: Record<string, string> = {
  breach_record: "Wyciek",
  account_registration: "Rejestracja",
  host_exposure: "Ekspozycja hosta",
  certificate: "Certyfikat",
  rdap_record: "RDAP/WHOIS",
  web_archive: "Archiwum web",
  demo_record: "Demo",
};

function pickAttr(attrs: Record<string, unknown>, keys: string[]): string | null {
  for (const k of keys) {
    const v = attrs[k];
    if (typeof v === "string" && v.length > 0) return v;
    if (typeof v === "number") return String(v);
  }
  return null;
}

export interface BreachDisplay {
  email: string | null;
  username: string | null;
  password: string | null;
  date: string | null;
  breachName: string;
}

export function breachDisplay(result: CanonicalResult): BreachDisplay {
  const a = result.attrs;
  return {
    email: pickAttr(a, ["email"]),
    username: pickAttr(a, ["username"]),
    password: pickAttr(a, ["password", "pass"]),
    date: pickAttr(a, ["breachDate", "created", "collected", "updated"]),
    breachName: result.title.replace(/^Wyciek:\s*/, ""),
  };
}

/** Jedna linia wyniku do wiadomosci Telegram, bez nazwy adaptera - patrz breachDisplay(). */
export function formatResultLine(result: CanonicalResult): string {
  if (result.kind === "breach_record") {
    const d = breachDisplay(result);
    const parts: string[] = [`🔓 <b>Wyciek: ${escapeHtml(d.breachName)}</b>`];
    if (d.email) parts.push(`✉️ ${escapeHtml(d.email)}`);
    else if (d.username) parts.push(`👤 ${escapeHtml(d.username)}`);
    if (d.password) parts.push(`🔑 <code>${escapeHtml(d.password)}</code>`);
    if (d.date) parts.push(`📅 ${escapeHtml(d.date)}`);
    if (result.sourceCount > 1) parts.push(`(${result.sourceCount} źródła)`);
    return parts.join("\n");
  }
  const label = KIND_LABELS[result.kind] ?? result.kind;
  return `📄 <b>${escapeHtml(label)}</b>: ${escapeHtml(result.title)}`;
}

export function formatSummary(results: CanonicalResult[], partial: boolean, durationMs: number): string {
  const breachCount = results.filter((r) => r.kind === "breach_record").length;
  const seconds = Math.round(durationMs / 1000);
  let header = `✅ Ukończono w ${seconds}s · ${results.length} wyników`;
  if (breachCount > 0) header += ` · ⚠ ${breachCount} wycieków`;
  if (partial) header += " (częściowe)";
  return header;
}
