"use client";

import { useEffect, useState } from "react";
import {
  ApiError,
  fetchCanonicalRecord,
  fetchRelatedRecords,
  type CanonicalRecordDetail,
  type RelatedRecord,
  type SourceRecordMeta,
} from "@/lib/api";

interface Props {
  canonicalRecordId: string;
  onClose: () => void;
}

type Tab = "overview" | "sources" | "related";

const KIND_LABELS: Record<string, string> = {
  breach_record: "Wyciek danych",
  account_registration: "Rejestracja konta",
  host_exposure: "Ekspozycja hosta",
  certificate: "Certyfikat TLS",
  rdap_record: "RDAP/WHOIS",
  web_archive: "Archiwum web",
  demo_record: "Demo",
};

export function DetailPanel({ canonicalRecordId, onClose }: Props) {
  const [tab, setTab] = useState<Tab>("overview");
  const [detail, setDetail] = useState<CanonicalRecordDetail | null>(null);
  const [related, setRelated] = useState<RelatedRecord[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingRelated, setLoadingRelated] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setDetail(null);
    setRelated(null);
    setErr(null);
    setTab("overview");
    setLoading(true);
    fetchCanonicalRecord(canonicalRecordId)
      .then(setDetail)
      .catch((e) => setErr(e instanceof ApiError ? e.message : "Błąd ładowania rekordu"))
      .finally(() => setLoading(false));
  }, [canonicalRecordId]);

  useEffect(() => {
    if (tab !== "related" || related !== null) return;
    setLoadingRelated(true);
    fetchRelatedRecords(canonicalRecordId)
      .then((r) => setRelated(r.related))
      .catch(() => setRelated([]))
      .finally(() => setLoadingRelated(false));
  }, [tab, canonicalRecordId, related]);

  // Close on Escape
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  return (
    <>
      <div className="detail-overlay" onClick={onClose} />
      <div className="detail-panel" role="dialog" aria-modal="true">
        {/* Header */}
        <div className="detail-header">
          <div className="detail-header-info">
            {detail && (
              <>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 6 }}>
                  <KindBadge kind={detail.kind} />
                  {detail.source_count > 1 && (
                    <span className="badge badge-green">{detail.source_count} źródeł</span>
                  )}
                </div>
                <h2>{detail.title}</h2>
                {detail.summary && <div className="muted" style={{ marginTop: 4 }}>{detail.summary}</div>}
              </>
            )}
            {loading && <div className="muted">Ładowanie...</div>}
            {err && <div className="error">{err}</div>}
          </div>
          <button className="detail-close ghost" onClick={onClose} aria-label="Zamknij">✕</button>
        </div>

        {/* Tabs */}
        <div className="detail-tabs">
          {(["overview", "sources", "related"] as Tab[]).map((t) => (
            <button key={t} className={`detail-tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
              {t === "overview" ? "Przegląd" : t === "sources" ? `Źródła (${detail?.sourceRecords.length ?? 0})` : "Powiązane"}
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="detail-body">
          {tab === "overview" && detail && <OverviewTab detail={detail} />}
          {tab === "sources" && detail && <SourcesTab sourceRecords={detail.sourceRecords} />}
          {tab === "related" && (
            <RelatedTab related={related} loading={loadingRelated} />
          )}
        </div>
      </div>
    </>
  );
}

// ---- Overview Tab ---- //
function OverviewTab({ detail }: { detail: CanonicalRecordDetail }) {
  const attrs = detail.attrs;
  const SKIP = new Set(["..."]); // nothing to skip; show all

  // Group attrs: top-level interesting fields first
  const PRIMARY_KEYS = ["email", "username", "source", "breachTable", "breachDate", "line", "ip", "domain", "phone"];
  const primaryEntries = PRIMARY_KEYS
    .filter((k) => attrs[k] != null && attrs[k] !== "")
    .map((k) => [k, attrs[k]] as [string, unknown]);

  const otherEntries = Object.entries(attrs)
    .filter(([k, v]) => !PRIMARY_KEYS.includes(k) && !SKIP.has(k) && v != null && v !== "" && !Array.isArray(v));

  const arrayEntries = Object.entries(attrs)
    .filter(([, v]) => Array.isArray(v));

  return (
    <div>
      {/* Meta */}
      <div className="detail-section">
        <div className="detail-section-title">Informacje ogólne</div>
        <div className="kv-list">
          <KVRow k="Typ" v={KIND_LABELS[detail.kind] ?? detail.kind} />
          <KVRow k="Pierwsze wykrycie" v={fmtDate(detail.first_seen)} />
          <KVRow k="Ostatnie wykrycie" v={fmtDate(detail.last_seen)} />
          <KVRow k="Liczba źródeł" v={String(detail.source_count)} />
          <KVRow k="ID rekordu" v={detail.id} mono />
        </div>
      </div>

      {/* Primary attrs */}
      {primaryEntries.length > 0 && (
        <div className="detail-section">
          <div className="detail-section-title">Dane identyfikatora</div>
          <div className="kv-list">
            {primaryEntries.map(([k, v]) => (
              <KVRow key={k} k={k} v={String(v)} mono />
            ))}
          </div>
        </div>
      )}

      {/* Other attrs */}
      {otherEntries.length > 0 && (
        <div className="detail-section">
          <div className="detail-section-title">Dodatkowe atrybuty</div>
          <div className="kv-list">
            {otherEntries.map(([k, v]) => (
              <KVRow key={k} k={k} v={String(v)} />
            ))}
          </div>
        </div>
      )}

      {/* Array attrs */}
      {arrayEntries.map(([k, v]) => (
        <div key={k} className="detail-section">
          <div className="detail-section-title">{k}</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
            {(v as unknown[]).map((item, i) => (
              <span key={i} className="badge">{String(item)}</span>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ---- Sources Tab ---- //
function SourcesTab({ sourceRecords }: { sourceRecords: SourceRecordMeta[] }) {
  if (sourceRecords.length === 0) {
    return <div className="muted">Brak powiązanych rekordów źródłowych.</div>;
  }
  return (
    <div>
      {sourceRecords.map((sr) => (
        <SourceRecordBox key={sr.id} sr={sr} />
      ))}
    </div>
  );
}

function SourceRecordBox({ sr }: { sr: SourceRecordMeta }) {
  // Flatten one level: top-level primitives + any attrs sub-object (e.g. local_import stores
  // password_hash inside raw.attrs rather than at the raw root).
  const flatRaw: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(sr.raw)) {
    if (k === "attrs" && v != null && typeof v === "object" && !Array.isArray(v)) {
      Object.assign(flatRaw, v);
    } else {
      flatRaw[k] = v;
    }
  }
  const rawEntries = Object.entries(flatRaw).filter(([, v]) => v != null && v !== "" && !Array.isArray(v) && typeof v !== "object");

  return (
    <div className="source-record-box">
      <div className="source-record-box-header">
        <span className="source-tag">{sr.sourceId}</span>
        <span className="muted">{fmtDate(sr.observedAt)}</span>
      </div>
      <div className="kv-list" style={{ marginTop: 6 }}>
        <KVRow k="source_record_id" v={sr.sourceRecordId} mono />
        {sr.urlCanonical && (
          <div className="kv-row">
            <span className="kv-key">link</span>
            <a href={sr.urlCanonical} target="_blank" rel="noopener noreferrer" className="kv-val" style={{ fontFamily: "inherit" }}>
              {sr.urlCanonical}
            </a>
          </div>
        )}
        {rawEntries.map(([k, v]) => (
          <KVRow key={k} k={k} v={String(v)} mono />
        ))}
      </div>
    </div>
  );
}

// ---- Related Tab ---- //
function RelatedTab({ related, loading }: { related: RelatedRecord[] | null; loading: boolean }) {
  if (loading) return <div className="loading-row"><div className="spinner" /> Ładowanie powiązań...</div>;
  if (!related) return null;
  if (related.length === 0) {
    return (
      <div className="empty-state">
        <div className="es-icon">🔗</div>
        <div className="es-msg">Brak powiązań</div>
        Żaden wspólny identyfikator (e-mail/username/IP/domena) nie łączy tego rekordu z innymi.
      </div>
    );
  }

  return (
    <div>
      <div className="muted" style={{ marginBottom: 12 }}>
        {related.length} powiązanych rekordów ze wspólnymi identyfikatorami
      </div>
      {related.map((r) => (
        <div key={r.id} className="source-record-box" style={{ marginBottom: 8 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 6 }}>
            <strong style={{ fontSize: 13, color: "var(--text)" }}>{r.title}</strong>
            <span className="badge">{KIND_LABELS[r.kind] ?? r.kind}</span>
          </div>
          {r.summary && <div className="muted" style={{ marginBottom: 6 }}>{r.summary}</div>}
          <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginBottom: 5 }}>
            {r.shared_keys.map((k) => (
              <span key={k} className="attr-pill mono">{k}</span>
            ))}
          </div>
          <div className="muted">{r.source_count} źródeł · {fmtDate(r.last_seen)}</div>
        </div>
      ))}
    </div>
  );
}

// ---- Micro-components ---- //
function KindBadge({ kind }: { kind: string }) {
  const cls: Record<string, string> = {
    breach_record: "badge-red",
    account_registration: "badge-amber",
    host_exposure: "badge-purple",
    certificate: "badge-blue",
    rdap_record: "badge-blue",
  };
  return <span className={`badge ${cls[kind] ?? ""}`}>{KIND_LABELS[kind] ?? kind}</span>;
}

function KVRow({ k, v, mono, masked }: { k: string; v: string; mono?: boolean; masked?: boolean }) {
  return (
    <div className="kv-row">
      <span className="kv-key">{k}</span>
      <span className={`kv-val ${mono ? "" : "muted"} ${masked ? "sensitive" : ""}`} style={masked ? { color: "var(--text-dim)", fontStyle: "italic", fontFamily: "inherit" } : undefined}>
        {v}
      </span>
    </div>
  );
}

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("pl-PL", { dateStyle: "short", timeStyle: "short" });
  } catch {
    return iso;
  }
}
