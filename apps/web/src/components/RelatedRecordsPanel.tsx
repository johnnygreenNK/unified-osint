"use client";

import { useState } from "react";
import { ApiError, fetchRelatedRecords, type RelatedRecord } from "@/lib/api";

interface RelatedRecordsPanelProps {
  canonicalRecordId: string;
}

/**
 * Pokazuje inne rekordy kanoniczne tego samego uzytkownika, ktore dziela
 * wspolny klucz korelacji (e-mail/username/ip/telefon/domena) z danym
 * rekordem - patrz GET /canonical-records/:id/related. To TYLKO sugestia
 * ("ten e-mail i ten adres IP widziano razem gdzie indziej"), nigdy
 * automatyczne scalenie rekordow.
 */
export function RelatedRecordsPanel({ canonicalRecordId }: RelatedRecordsPanelProps) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [related, setRelated] = useState<RelatedRecord[] | null>(null);

  async function toggle(): Promise<void> {
    if (open) {
      setOpen(false);
      return;
    }
    setOpen(true);
    if (related !== null) return; // juz pobrane - nie odpytuj ponownie przy kazdym otwarciu.

    setLoading(true);
    setError(null);
    try {
      const result = await fetchRelatedRecords(canonicalRecordId);
      setRelated(result.related);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Nie udalo sie wczytac powiazanych rekordow");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ marginTop: 4 }}>
      <button type="button" className="secondary" onClick={toggle} style={{ fontSize: 12, padding: "4px 8px" }}>
        {open ? "Zwin powiazane" : "Pokaz powiazane rekordy"}
      </button>

      {open && (
        <div style={{ marginTop: 8, paddingLeft: 12, borderLeft: "2px solid #262b35" }}>
          {loading && <p className="muted">Szukam powiazanych rekordow...</p>}
          {error && <div className="error">{error}</div>}
          {!loading && !error && related !== null && related.length === 0 && (
            <p className="muted">Brak powiazanych rekordow (zaden wspolny e-mail/username/IP/telefon/domena).</p>
          )}
          {related?.map((r) => (
            <div key={r.id} className="result-item">
              <div className="row" style={{ justifyContent: "space-between" }}>
                <strong style={{ fontSize: 13 }}>{r.title}</strong>
                <span className="muted" style={{ fontSize: 11 }}>
                  {r.source_count} zrodlo/a
                </span>
              </div>
              {r.summary && <div className="muted">{r.summary}</div>}
              <div className="row" style={{ marginTop: 4 }}>
                {r.shared_keys.map((k) => (
                  <span key={k} className="badge">
                    {k}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
