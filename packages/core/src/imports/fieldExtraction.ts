import { normalizeEmail, normalizeIp, normalizePhone, normalizeDomain } from "../dedup/normalize.js";

/**
 * Aliasy nazw kolumn rozpoznawane w importowanych plikach (CSV/SQL) -
 * te same rodziny pol korelacji co `CORRELATION_ATTR_ALIASES` w dedupEngine,
 * poszerzone o typowe naglowki uzywane w zrzutach wyciekow.
 */
const FIELD_ALIASES: Record<"email" | "username" | "ip" | "phone" | "domain", string[]> = {
  email: ["email", "e-mail", "mail", "emailaddress", "email_address"],
  username: ["username", "user", "login", "nick", "nickname", "user_name"],
  ip: ["ip", "ipaddress", "ip_address", "lastip", "last_ip"],
  phone: ["phone", "phonenumber", "phone_number", "mobile", "tel"],
  domain: ["domain", "website", "site"],
};

export interface ExtractedFields {
  email: string | null;
  username: string | null;
  ip: string | null;
  phone: string | null;
  domain: string | null;
}

function findField(row: Record<string, string | null>, aliases: string[]): string | null {
  const keys = Object.keys(row);
  for (const alias of aliases) {
    const key = keys.find((k) => k.trim().toLowerCase() === alias);
    if (key) {
      const value = row[key];
      if (value && value.trim().length > 0) return value.trim();
    }
  }
  return null;
}

/** Wyodrebnia i normalizuje pola korelacji z jednego wiersza importu (naglowki case-insensitive). */
export function extractFields(row: Record<string, string | null>): ExtractedFields {
  const rawEmail = findField(row, FIELD_ALIASES.email);
  const rawUsername = findField(row, FIELD_ALIASES.username);
  const rawIp = findField(row, FIELD_ALIASES.ip);
  const rawPhone = findField(row, FIELD_ALIASES.phone);
  const rawDomain = findField(row, FIELD_ALIASES.domain);

  return {
    email: rawEmail ? normalizeEmail(rawEmail) : null,
    username: rawUsername ? rawUsername.trim().toLowerCase() : null,
    ip: rawIp ? normalizeIp(rawIp) : null,
    phone: rawPhone ? normalizePhone(rawPhone) : null,
    domain: rawDomain ? normalizeDomain(rawDomain) : null,
  };
}
