import type { PoolClient } from "pg";
import type { AdapterRecord } from "../contracts/adapter.js";
import { normalizeUrl, normalizeText } from "./normalize.js";
import {
  fingerprintBySourceId,
  fingerprintByUrl,
  fingerprintByContent,
  type FingerprintType,
} from "./fingerprint.js";
import { NORMALIZATION_VERSION } from "./normalize.js";

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
function pickStrongFingerprint(
  record: AdapterRecord,
  sourceId: string
): { type: FingerprintType; value: string } {
  if (record.canonicalUrl) {
    return { type: "url", value: fingerprintByUrl(normalizeUrl(record.canonicalUrl)) };
  }
  if ((record.kind === "document" || record.kind === "paste") && record.summary) {
    return { type: "content", value: fingerprintByContent(normalizeText(record.summary)) };
  }
  return { type: "id", value: fingerprintBySourceId(sourceId, record.sourceRecordId) };
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

  return {
    canonicalId,
    sourceRecordId,
    isNewLink,
    sourceCount: countRes.rows[0]!.source_count,
  };
}
