import type { PoolClient } from "pg";
import type { AdapterRecord } from "../contracts/adapter.js";
import { normalizeUrl, normalizeText, normalizeEmail, normalizeIp, normalizePhone, normalizeDomain } from "./normalize.js";
import {
  fingerprintBySourceId,
  fingerprintByUrl,
  fingerprintByContent,
  fingerprintByCredential,
  type FingerprintType,
} from "./fingerprint.js";
import { NORMALIZATION_VERSION } from "./normalize.js";

/** Typ klucza korelacji - musi zgadzac sie z check-constraint `record_correlation_keys.key_type`. */
export type CorrelationKeyType = "email" | "username" | "ip" | "phone" | "domain";

/**
 * Atrybuty adaptera, z ktorych wydobywamy klucze korelacji tozsamosci -
 * ODREBNE od fingerprintow dedupu (patrz naglowek pliku migracji 0008).
 * Nazwy atrybutow nie sa znormalizowanym kontraktem miedzy adapterami
 * (`AdapterRecord.attrs` to wolny bag), wiec sprawdzamy kilka popularnych
 * aliasow uzywanych przez istniejace adaptery (np. Snusbase zwraca `lastip`).
 */
const CORRELATION_ATTR_ALIASES: Record<CorrelationKeyType, string[]> = {
  email: ["email"],
  username: ["username"],
  ip: ["ip", "lastip", "last_ip"],
  phone: ["phone", "phonenumber", "phone_number"],
  domain: ["domain"],
};

export function extractCorrelationKeys(record: AdapterRecord): { type: CorrelationKeyType; value: string }[] {
  const attrs = record.attrs ?? {};
  const keys: { type: CorrelationKeyType; value: string }[] = [];

  for (const [type, aliases] of Object.entries(CORRELATION_ATTR_ALIASES) as [CorrelationKeyType, string[]][]) {
    for (const alias of aliases) {
      const raw = attrs[alias];
      if (typeof raw !== "string" || raw.length === 0) continue;

      const normalized =
        type === "email"
          ? normalizeEmail(raw)
          : type === "ip"
            ? normalizeIp(raw)
            : type === "phone"
              ? normalizePhone(raw)
              : type === "domain"
                ? normalizeDomain(raw)
                : raw.trim().toLowerCase();

      if (normalized) keys.push({ type, value: normalized });
      break; // pierwszy obecny alias dla danego typu wygrywa - nie duplikujemy tego samego typu z dwoch aliasow.
    }
  }

  return keys;
}

export interface DedupInput {
  ownerId: string;
  sourceId: string;
  searchId: string;
  record: AdapterRecord;
}

export interface DedupOutcome {
  canonicalId: string;
  sourceRecordId: string;
  /** True, jesli to pierwsze polaczenie tego source_record z tym kanonicznym rekordem (nie retry). */
  isNewLink: boolean;
  sourceCount: number;
}

/** Maksymalny rozmiar `raw` zapisywany w bazie (minimalizacja danych - patrz docs/deduplication.md). */
const MAX_RAW_BYTES = 32 * 1024;

/**
 * Wybiera najsilniejszy dostepny fingerprint dla rekordu:
 *  1) URL (laczy duplikaty MIEDZY zrodlami - to jest sedno wymogu "dwa zrodla, ten sam rekord"),
 *  2) trescia (TYLKO kind=document/paste),
 *  3) identyfikator w ramach zrodla (fallback - wykrywa duplikaty tylko WEWNATRZ jednego zrodla).
 */
/** Aliasy pol w `attrs`, z ktorych wydobywamy "sekret" wyciekowy (patrz fingerprintByCredential). */
const SECRET_ATTR_ALIASES = ["password", "pass", "hash", "phash"];

export function pickStrongFingerprint(
  record: AdapterRecord,
  sourceId: string
): { type: FingerprintType; value: string } {
  if (record.canonicalUrl) {
    return { type: "url", value: fingerprintByUrl(normalizeUrl(record.canonicalUrl)) };
  }
  if ((record.kind === "document" || record.kind === "paste") && record.summary) {
    return { type: "content", value: fingerprintByContent(normalizeText(record.summary)) };
  }
  // breach_record: dwa zrodla (np. Snusbase i LeakCheck) czesto agreguja te
  // sama bazowa wyciekniecie/logi stealerow. Jesli oba zwracaja ta sama pare
  // identyfikator+sekret, to ten sam rekord - laczymy go w jeden kanoniczny
  // wpis zamiast pokazywac duplikat per zrodlo.
  if (record.kind === "breach_record") {
    const attrs = record.attrs ?? {};
    const identity =
      firstNonEmptyString(attrs.email) ?? firstNonEmptyString(attrs.username);
    const secret = SECRET_ATTR_ALIASES.map((k) => firstNonEmptyString(attrs[k])).find((v) => v != null);
    if (identity && secret) {
      return { type: "content", value: fingerprintByCredential(identity, secret) };
    }
  }
  return { type: "id", value: fingerprintBySourceId(sourceId, record.sourceRecordId) };
}

function firstNonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function truncateRaw(raw: unknown): unknown {
  const json = JSON.stringify(raw ?? null);
  if (Buffer.byteLength(json, "utf8") <= MAX_RAW_BYTES) return raw;
  return { truncated: true, preview: json.slice(0, MAX_RAW_BYTES) };
}

/**
 * Wstawia/laczy jeden znormalizowany rekord adaptera z warstwa kanoniczna.
 * Bezpieczne pod rownolegle wywolania dla tego samego rekordu: kazdy krok
 * uzywa `INSERT ... ON CONFLICT`, ktory jest atomowy na poziomie wiersza
 * w Postgresie - nie wymaga dodatkowej blokady advisory.
 *
 * Wywolujacy MUSI przekazac klienta pracujacego w kontekscie `withAppContext`
 * (app.user_id / app.role juz ustawione), bo polityki RLS na tych tabelach
 * sprawdzaja wlasciciela.
 */
export async function upsertNormalizedRecord(
  client: PoolClient,
  input: DedupInput
): Promise<DedupOutcome> {
  const { ownerId, sourceId, searchId, record } = input;
  const normalizedUrl = record.canonicalUrl ? normalizeUrl(record.canonicalUrl) : null;
  const rawToStore = truncateRaw(record.raw);
  const rawHash = fingerprintByContent(JSON.stringify(rawToStore));

  // 1) Upsert source_records (warstwa 1: identyczny identyfikator zrodlowy).
  const sourceRecordRes = await client.query<{ id: string }>(
    `insert into source_records (owner_scope, owner_id, source_id, source_record_id, search_id, url_canonical, raw_hash, raw, observed_at)
     values ('user', $1, $2, $3, $4, $5, $6, $7, coalesce($8, now()))
     on conflict (owner_scope, owner_id, source_id, source_record_id)
     do update set raw = excluded.raw, raw_hash = excluded.raw_hash, observed_at = excluded.observed_at, search_id = excluded.search_id
     returning id`,
    [
      ownerId,
      sourceId,
      record.sourceRecordId,
      searchId,
      normalizedUrl,
      rawHash,
      JSON.stringify(rawToStore),
      record.observedAt,
    ]
  );
  const sourceRecordId = sourceRecordRes.rows[0]!.id;

  // 2) Wybierz fingerprint i znajdz/utworz rekord kanoniczny (ON CONFLICT = atomowe scalenie).
  const strong = pickStrongFingerprint(record, sourceId);
  const canonicalRes = await client.query<{ id: string; source_count: number }>(
    `insert into canonical_records (owner_scope, owner_id, kind, canonical_key, title, summary, attrs, norm_version, last_seen)
     values ('user', $1, $2, $3, $4, $5, $6, $7, now())
     on conflict (owner_scope, owner_id, kind, canonical_key)
     do update set last_seen = now()
     returning id, source_count`,
    [
      ownerId,
      record.kind,
      strong.value,
      record.title,
      record.summary,
      JSON.stringify(record.attrs ?? {}),
      NORMALIZATION_VERSION,
    ]
  );
  const canonicalId = canonicalRes.rows[0]!.id;

  // 3) Zapisz fingerprint uzyty do tego polaczenia (do przyszlych wyszukiwan po fp).
  await client.query(
    `insert into record_fingerprints (canonical_id, owner_scope, owner_id, fp_type, fp_value, norm_version)
     values ($1, 'user', $2, $3, $4, $5)
     on conflict (owner_scope, owner_id, fp_type, fp_value, norm_version) do nothing`,
    [canonicalId, ownerId, strong.type, strong.value, NORMALIZATION_VERSION]
  );

  // 4) Polacz source_record z rekordem kanonicznym (idempotentne - retry nie dubluje).
  const linkRes = await client.query(
    `insert into record_sources (canonical_id, source_record_id, link_type, confidence, observed_at)
     values ($1, $2, 'same', 1.0, now())
     on conflict (canonical_id, source_record_id) do nothing
     returning canonical_id`,
    [canonicalId, sourceRecordId]
  );
  const isNewLink = linkRes.rows.length > 0;

  // 5) source_count = prawda wyliczona z liczby polaczen, nie inkrementacja (odporne na retry).
  const countRes = await client.query<{ source_count: number }>(
    `update canonical_records
     set source_count = (select count(*) from record_sources where canonical_id = $1)
     where id = $1
     returning source_count`,
    [canonicalId]
  );

  // 6) Klucze korelacji tozsamosci (e-mail/username/ip/telefon/domena) -
  // ODREBNA warstwa od dedupu, patrz naglowek migracji 0008. Nigdy nie
  // laczy automatycznie rekordow kanonicznych, tylko zapisuje sygnal do
  // pozniejszego odpytania przez GET /canonical-records/:id/related.
  for (const key of extractCorrelationKeys(record)) {
    await client.query(
      `insert into record_correlation_keys (canonical_id, owner_scope, owner_id, key_type, key_value)
       values ($1, 'user', $2, $3, $4)
       on conflict (owner_scope, owner_id, canonical_id, key_type, key_value) do nothing`,
      [canonicalId, ownerId, key.type, key.value]
    );
  }

  return {
    canonicalId,
    sourceRecordId,
    isNewLink,
    sourceCount: countRes.rows[0]!.source_count,
  };
}
