"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  API_BASE_URL,
  ApiError,
  autoLogin,
  fetchMe,
  fetchSources,
  startSearch,
  uploadImport,
  type ImportBatchResult,
  type SourceInfo,
} from "@/lib/api";
import { DetailPanel } from "@/components/DetailPanel";

// ---- Constants ---- //
const QUERY_TYPE_LABELS: Record<string, string> = {
  email: "E-mail",
  username: "Username",
  name: "Imię/nazwisko",
  domain: "Domena",
  ip: "Adres IP",
  phone: "Telefon",
  hash: "Hash",
  url: "URL / repo",
  text: "Tekst",
};
const QUERY_TYPES = Object.keys(QUERY_TYPE_LABELS);

const KIND_LABELS: Record<string, string> = {
  breach_record: "Wyciek",
  account_registration: "Rejestracja",
  host_exposure: "Ekspozycja hosta",
  certificate: "Certyfikat",
  rdap_record: "RDAP/WHOIS",
  web_archive: "Archiwum web",
  demo_record: "Demo",
  default: "Rekord",
};

const KIND_BADGE_CLASS: Record<string, string> = {
  breach_record: "badge-red",
  account_registration: "badge-amber",
  host_exposure: "badge-purple",
  certificate: "badge-blue",
  rdap_record: "badge-blue",
  web_archive: "",
  demo_record: "",
};

const SORT_OPTIONS = [
  { value: "priority", label: "Priorytet (domyślnie)" },
  { value: "source_count", label: "Liczba źródeł" },
  { value: "kind", label: "Typ rekordu" },
  { value: "title", label: "Alfabetycznie" },
];

// ---- Types ---- //
interface TaskState {
  sourceId: string;
  status: string;
  resultCount?: number;
  errorMessage?: string;
  latencyMs?: number;
}

interface CanonicalResult {
  canonicalRecordId: string;
  sourceId: string;
  kind: string;
  title: string;
  sourceCount: number;
  priority: number;
  hasCredential: boolean;
}

interface LiveEvent {
  id: string;
  type: string;
  payload: Record<string, unknown>;
}

// ---- Helpers ---- //
function calcPriority(kind: string, sourceCount: number): number {
  const base: Record<string, number> = {
    breach_record: 90,
    account_registration: 70,
    credential_leak: 80,
    host_exposure: 50,
    certificate: 35,
    rdap_record: 30,
    web_archive: 15,
    demo_record: 5,
  };
  return (base[kind] ?? 25) + Math.min(sourceCount - 1, 5) * 4;
}

function statusDotClass(status: string): string {
  if (status === "active" || status === "succeeded") return "dot dot-ok";
  if (status === "degraded" || status === "running" || status === "pending") return "dot dot-warn";
  if (status === "error" || status === "failed") return "dot dot-error";
  return "dot dot-muted";
}

function resultReason(r: CanonicalResult): string {
  const reasons: string[] = [];
  if (r.hasCredential) reasons.push("wskaźnik ekspozycji danych uwierzytelniających");
  if (r.sourceCount > 1) reasons.push(`${r.sourceCount} niezależne źródła`);
  if (r.kind === "breach_record") reasons.push("dane z wycieku");
  if (r.kind === "account_registration") reasons.push("znaleziono konto");
  return reasons.length ? reasons.join(" · ") : KIND_LABELS[r.kind] ?? r.kind;
}

// ---- Main Page ---- //
export default function DashboardPage() {
  const [sessionReady, setSessionReady] = useState(false);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [sources, setSources] = useState<SourceInfo[]>([]);
  const [selectedSources, setSelectedSources] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [queryType, setQueryType] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [searchId, setSearchId] = useState<string | null>(null);
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [skipped, setSkipped] = useState<{ sourceId: string; reason: string }[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState("priority");
  const [filterKind, setFilterKind] = useState("");
  const [filterSource, setFilterSource] = useState("");
  const [importBusy, setImportBusy] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [importResult, setImportResult] = useState<ImportBatchResult | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const importInputRef = useRef<HTMLInputElement | null>(null);

  // Auth
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try { await fetchMe(); }
      catch {
        try { await autoLogin(); }
        catch { if (!cancelled) setSessionError("Nie udało się uwierzytelnić automatycznie."); return; }
      }
      if (!cancelled) setSessionReady(true);
    })();
    return () => { cancelled = true; };
  }, []);

  // Sources
  useEffect(() => {
    fetchSources().then((res) => setSources(res.sources)).catch(() => {});
  }, []);

  // Live search events: tied to searchId so a remount (e.g. Fast Refresh)
  // reopens the connection instead of leaving it closed forever.
  useEffect(() => {
    if (!searchId) return;
    const es = new EventSource(`${API_BASE_URL}/searches/${searchId}/events`, { withCredentials: true });
    eventSourceRef.current = es;
    const h = (type: string) => (ev: MessageEvent) => {
      try {
        setEvents((prev) => [...prev, { id: ev.lastEventId, type, payload: JSON.parse(ev.data) }]);
      } catch {
        // ignore malformed event payload
      }
    };
    for (const t of ["search.started", "task.status", "result.added", "result.merged", "task.error", "search.completed"]) {
      es.addEventListener(t, h(t));
    }
    return () => {
      es.close();
      if (eventSourceRef.current === es) eventSourceRef.current = null;
    };
  }, [searchId]);

  // Compatible sources for chosen query type
  const { compatibleSources, incompatibleSources } = useMemo(() => {
    if (!queryType) return { compatibleSources: sources, incompatibleSources: [] as SourceInfo[] };
    return {
      compatibleSources: sources.filter((s) => s.queryTypes.includes(queryType)),
      incompatibleSources: sources.filter((s) => !s.queryTypes.includes(queryType)),
    };
  }, [sources, queryType]);

  useEffect(() => {
    if (!queryType) return;
    setSelectedSources((prev) => new Set([...prev].filter((id) => sources.find((s) => s.id === id)?.queryTypes.includes(queryType))));
  }, [queryType, sources]);

  function toggleSource(id: string) {
    setSelectedSources((prev) => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  }

  // Build deduplicated canonical results from SSE events.
  // result.added and result.merged carry the same payload shape - the only
  // difference is whether the canonical record already existed before this
  // event. A record's first sighting in a given search can be a merge (e.g.
  // it was already known from an earlier search), so both upsert the map.
  const results = useMemo<CanonicalResult[]>(() => {
    const map = new Map<string, CanonicalResult>();
    for (const ev of events) {
      if (ev.type === "result.added" || ev.type === "result.merged") {
        const p = ev.payload;
        const id = p.canonicalRecordId as string;
        const kind = p.kind as string;
        const sourceCount = p.sourceCount as number;
        // Heuristic: detect credential indicator from title or kind
        const hasCredential =
          kind === "breach_record" &&
          (String(p.title ?? "").toLowerCase().includes("wyciek") ||
            sourceCount > 0);
        map.set(id, {
          canonicalRecordId: id,
          sourceId: p.sourceId as string,
          kind,
          title: p.title as string,
          sourceCount,
          priority: calcPriority(kind, sourceCount),
          hasCredential,
        });
      }
    }
    return [...map.values()];
  }, [events]);

  // Task states
  const taskStates = useMemo(() => {
    const map = new Map<string, TaskState>();
    for (const ev of events) {
      if (ev.type === "task.status") {
        const p = ev.payload;
        map.set(p.sourceId as string, {
          sourceId: p.sourceId as string,
          status: p.status as string,
          resultCount: p.resultCount as number | undefined,
          latencyMs: p.latencyMs as number | undefined,
        });
      } else if (ev.type === "task.error") {
        const p = ev.payload;
        map.set(p.sourceId as string, { sourceId: p.sourceId as string, status: "failed", errorMessage: p.message as string | undefined });
      }
    }
    return map;
  }, [events]);

  const completedEvent = events.find((ev) => ev.type === "search.completed");
  const isRunning = !!searchId && !completedEvent;

  // Filter + sort
  const displayResults = useMemo(() => {
    let r = results;
    if (filterKind) r = r.filter((x) => x.kind === filterKind);
    if (filterSource) r = r.filter((x) => x.sourceId === filterSource);
    switch (sortBy) {
      case "priority": return [...r].sort((a, b) => b.priority - a.priority);
      case "source_count": return [...r].sort((a, b) => b.sourceCount - a.sourceCount);
      case "kind": return [...r].sort((a, b) => a.kind.localeCompare(b.kind));
      case "title": return [...r].sort((a, b) => a.title.localeCompare(b.title));
      default: return r;
    }
  }, [results, filterKind, filterSource, sortBy]);

  const credResults = useMemo(
    () => displayResults.filter((r) => r.kind === "breach_record"),
    [displayResults]
  );
  const otherResults = useMemo(
    () => displayResults.filter((r) => r.kind !== "breach_record"),
    [displayResults]
  );

  // Summary stats
  const stats = useMemo(() => {
    const unique_kinds = new Set(results.map((r) => r.kind));
    const unique_sources = new Set(results.map((r) => r.sourceId));
    const breach_count = results.filter((r) => r.kind === "breach_record").length;
    const high_conf = results.filter((r) => r.sourceCount >= 2).length;
    const registrations = results.filter((r) => r.kind === "account_registration").length;
    return {
      total: results.length,
      breach_count,
      high_conf,
      registrations,
      unique_kinds: unique_kinds.size,
      unique_sources: unique_sources.size,
    };
  }, [results]);

  // Known kinds / sources for filter dropdowns
  const knownKinds = useMemo(() => [...new Set(results.map((r) => r.kind))].sort(), [results]);
  const knownSources = useMemo(() => [...new Set(results.map((r) => r.sourceId))].sort(), [results]);

  // Start search
  const onSearchSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    setEvents([]);
    setSkipped([]);
    setSelectedId(null);
    eventSourceRef.current?.close();

    try {
      const res = await startSearch(query, queryType || undefined, selectedSources.size > 0 ? [...selectedSources] : undefined);
      setSearchId(res.searchId);
      setSkipped(res.skippedSourceIds);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Nie udało się uruchomić wyszukiwania");
    } finally {
      setBusy(false);
    }
  }, [query, queryType, selectedSources]);

  const onImportFileSelected = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setImportBusy(true);
    setImportError(null);
    setImportResult(null);
    try {
      const res = await uploadImport(file);
      setImportResult(res);
      fetchSources().then((r) => setSources(r.sources)).catch(() => {});
    } catch (err) {
      setImportError(err instanceof ApiError ? err.message : "Import nie powiódł się");
    } finally {
      setImportBusy(false);
    }
  }, []);

  if (sessionError) {
    return (
      <div style={{ padding: 40, maxWidth: 500, margin: "0 auto" }}>
        <h1 style={{ fontSize: 18, fontWeight: 700, marginBottom: 12 }}>UnifiedOSINT</h1>
        <div className="error">{sessionError}</div>
      </div>
    );
  }
  if (!sessionReady) {
    return (
      <div style={{ padding: 40, display: "flex", alignItems: "center", gap: 10 }}>
        <div className="spinner" /> <span className="muted">Ładowanie sesji...</span>
      </div>
    );
  }

  return (
    <div className="app-shell">
      {/* ---- LEFT SIDEBAR: Search form ---- */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <h1>UnifiedOSINT</h1>
          <div className="subtitle">Intelligence Platform</div>
        </div>
        <div className="sidebar-body">
          <form onSubmit={onSearchSubmit} className="col">
            <div>
              <label className="field-label">Zapytanie</label>
              <input
                type="text"
                placeholder="email, username, IP, domena..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                required
              />
            </div>

            <div>
              <label className="field-label">Typ</label>
              <div className="segmented">
                <button type="button" className={queryType === "" ? "seg-btn seg-active" : "seg-btn"} onClick={() => setQueryType("")}>
                  Auto
                </button>
                {QUERY_TYPES.map((t) => (
                  <button type="button" key={t} className={queryType === t ? "seg-btn seg-active" : "seg-btn"} onClick={() => setQueryType(t)}>
                    {QUERY_TYPE_LABELS[t]}
                  </button>
                ))}
              </div>
            </div>

            <details>
              <summary className="field-label" style={{ marginBottom: 0 }}>
                Źródła{selectedSources.size > 0 ? ` (${selectedSources.size} wybrano)` : " (wszystkie pasujące)"}
              </summary>
              <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 5 }}>
                {compatibleSources.map((s) => (
                  <label key={s.id} className="source-chip" title={s.status}>
                    <input type="checkbox" checked={selectedSources.has(s.id)} onChange={() => toggleSource(s.id)} />
                    <span className={statusDotClass(s.status)} />
                    {s.name}
                  </label>
                ))}
                {compatibleSources.length === 0 && <span className="muted">Brak źródeł dla tego typu.</span>}
              </div>
              {incompatibleSources.length > 0 && (
                <div style={{ marginTop: 6, display: "flex", flexWrap: "wrap", gap: 5 }}>
                  {incompatibleSources.map((s) => (
                    <span key={s.id} className="source-chip source-chip-disabled" title={`Nie obsługuje: ${queryType}`}>
                      <span className={statusDotClass(s.status)} /> {s.name}
                    </span>
                  ))}
                </div>
              )}
            </details>

            {skipped.length > 0 && (
              <details>
                <summary className="muted">{skipped.length} źródeł pominiętych</summary>
                <ul style={{ marginTop: 6, paddingLeft: 14 }}>
                  {skipped.map((s) => <li key={s.sourceId} className="muted">{s.sourceId}: {s.reason}</li>)}
                </ul>
              </details>
            )}

            {error && <div className="error">{error}</div>}

            <button type="submit" disabled={busy || !query.trim()}>
              {busy ? "Uruchamiam..." : isRunning ? "🔄 Trwa wyszukiwanie..." : "Szukaj"}
            </button>

            {searchId && completedEvent && (
              <div className="muted" style={{ textAlign: "center" }}>
                Ukończono w {Math.round((completedEvent.payload.durationMs as number) / 1000)} s
                {completedEvent.payload.partial ? " (częściowe)" : ""}
              </div>
            )}
          </form>

          {/* Import własnych dumpów (CSV/SQL) */}
          <div style={{ marginTop: 16 }}>
            <div className="section-label">Własny import (CSV / SQL)</div>
            <input
              ref={importInputRef}
              type="file"
              accept=".csv,.sql,.txt"
              style={{ display: "none" }}
              onChange={onImportFileSelected}
            />
            <button
              type="button"
              className="ghost btn-sm"
              style={{ width: "100%" }}
              disabled={importBusy}
              onClick={() => importInputRef.current?.click()}
            >
              {importBusy ? "Wgrywam..." : "📤 Wgraj plik wycieku"}
            </button>
            {importError && <div className="error" style={{ marginTop: 6 }}>{importError}</div>}
            {importResult && (
              <div className="muted" style={{ marginTop: 6, fontSize: 12 }}>
                ✓ {importResult.filename}: {importResult.rowCount} wierszy zaimportowanych
                {importResult.skippedCount > 0 ? `, ${importResult.skippedCount} pominiętych` : ""}.
                Wybierz źródło &quot;Własne importy&quot; i wyszukaj wartość z pliku.
              </div>
            )}
          </div>

          {/* Task status */}
          {taskStates.size > 0 && (
            <div style={{ marginTop: 16 }}>
              <div className="section-label">Źródła</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {[...taskStates.values()].map((t) => (
                  <div key={t.sourceId} style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 12 }}>
                    <span className={statusDotClass(t.status)} />
                    <span style={{ flex: 1, color: "var(--text-muted)" }}>{t.sourceId}</span>
                    {typeof t.resultCount === "number" && <span style={{ color: "var(--text-dim)", fontSize: 11 }}>{t.resultCount} rek.</span>}
                    {t.latencyMs && <span style={{ color: "var(--text-dim)", fontSize: 11 }}>{t.latencyMs}ms</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </aside>

      {/* ---- MAIN CONTENT ---- */}
      <main className="main-content">
        {!searchId && (
          <div className="empty-state">
            <div className="es-icon">🔍</div>
            <div className="es-msg">Gotowy do wyszukiwania</div>
            Wprowadź zapytanie w lewym panelu, aby rozpocząć analizę.
          </div>
        )}

        {searchId && (
          <>
            {/* Summary cards */}
            <div className="summary-grid">
              <div className="summary-card">
                <div className="sc-value">{stats.total}</div>
                <div className="sc-label">Wyniki ogółem</div>
              </div>
              <div className={`summary-card ${stats.breach_count > 0 ? "sc-red" : ""}`}>
                <div className="sc-value">{stats.breach_count}</div>
                <div className="sc-label">Wycieki danych</div>
              </div>
              <div className={`summary-card ${stats.registrations > 0 ? "sc-amber" : ""}`}>
                <div className="sc-value">{stats.registrations}</div>
                <div className="sc-label">Rejestracje kont</div>
              </div>
              <div className={`summary-card ${stats.high_conf > 0 ? "sc-green" : ""}`}>
                <div className="sc-value">{stats.high_conf}</div>
                <div className="sc-label">Wys. pewność (≥2 źródła)</div>
              </div>
              <div className="summary-card sc-blue">
                <div className="sc-value">{stats.unique_sources}</div>
                <div className="sc-label">Unikalne źródła</div>
              </div>
              <div className="summary-card">
                <div className="sc-value">{stats.unique_kinds}</div>
                <div className="sc-label">Typy rekordów</div>
              </div>
            </div>

            {/* Loading indicator */}
            {isRunning && (
              <div className="loading-row">
                <div className="spinner" />
                Trwa pobieranie danych ze źródeł...
              </div>
            )}

            {/* Credential / Breach section */}
            {credResults.length > 0 && (
              <div className="cred-section">
                <div className="cred-section-header">
                  <span className="badge badge-red">⚠ Dane wrażliwe</span>
                  <span className="cred-section-title">Wycieki danych ({credResults.length})</span>
                </div>
                {credResults.map((r) => (
                  <BreachCard key={r.canonicalRecordId} result={r} active={selectedId === r.canonicalRecordId} onClick={() => setSelectedId(r.canonicalRecordId)} />
                ))}
              </div>
            )}

            {/* Filter bar */}
            {results.length > 0 && (
              <div className="filter-bar">
                <select value={sortBy} onChange={(e) => setSortBy(e.target.value)} style={{ minWidth: 160 }}>
                  {SORT_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
                <select value={filterKind} onChange={(e) => setFilterKind(e.target.value)}>
                  <option value="">Wszystkie typy</option>
                  {knownKinds.map((k) => <option key={k} value={k}>{KIND_LABELS[k] ?? k}</option>)}
                </select>
                <select value={filterSource} onChange={(e) => setFilterSource(e.target.value)}>
                  <option value="">Wszystkie źródła</option>
                  {knownSources.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
                {(filterKind || filterSource) && (
                  <button type="button" className="ghost btn-sm" onClick={() => { setFilterKind(""); setFilterSource(""); }}>
                    ✕ Wyczyść filtry
                  </button>
                )}
                <span className="filter-count">{displayResults.length} z {results.length} rekordów</span>
              </div>
            )}

            {/* Other results */}
            {otherResults.length > 0 && (
              <>
                <div className="section-label" style={{ marginBottom: 8 }}>Pozostałe wyniki</div>
                <div className="result-list">
                  {otherResults.map((r) => (
                    <ResultCard key={r.canonicalRecordId} result={r} active={selectedId === r.canonicalRecordId} onClick={() => setSelectedId(r.canonicalRecordId)} />
                  ))}
                </div>
              </>
            )}

            {/* Empty state */}
            {results.length === 0 && completedEvent && (
              <div className="empty-state">
                <div className="es-icon">📭</div>
                <div className="es-msg">Brak wyników</div>
                Żadne ze źródeł nie znalazło danych dla tego zapytania.
              </div>
            )}

            {results.length === 0 && !completedEvent && !isRunning && (
              <div className="empty-state"><span className="muted">Oczekiwanie na wyniki...</span></div>
            )}
          </>
        )}
      </main>

      {/* ---- DETAIL PANEL ---- */}
      {selectedId && (
        <DetailPanel canonicalRecordId={selectedId} onClose={() => setSelectedId(null)} />
      )}
    </div>
  );
}

// ---- Sub-components ---- //

function kindBadge(kind: string) {
  const cls = KIND_BADGE_CLASS[kind] ?? "";
  return <span className={`badge ${cls}`}>{KIND_LABELS[kind] ?? kind}</span>;
}

function BreachCard({ result, active, onClick }: { result: CanonicalResult; active: boolean; onClick: () => void }) {
  return (
    <div className={`cred-item ${active ? "active" : ""}`} onClick={onClick} role="button" tabIndex={0} onKeyDown={(e) => e.key === "Enter" && onClick()}>
      <div className="cred-item-top">
        <span className="cred-item-title">{result.title}</span>
        <div style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
          {result.sourceCount > 1 && <span className="badge badge-green">{result.sourceCount} źródła</span>}
          <span className="badge badge-red">Wyciek</span>
        </div>
      </div>
      <div className="cred-attrs">
        <span className="attr-pill"><strong>źródło:</strong>{result.sourceId}</span>
        <span className="attr-pill sensitive">⚠ dane wrażliwe</span>
      </div>
    </div>
  );
}

function ResultCard({ result, active, onClick }: { result: CanonicalResult; active: boolean; onClick: () => void }) {
  return (
    <div className={`result-card ${active ? "active" : ""}`} onClick={onClick} role="button" tabIndex={0} onKeyDown={(e) => e.key === "Enter" && onClick()}>
      <div className="result-card-header">
        <div style={{ flex: 1, minWidth: 0 }}>
          {kindBadge(result.kind)}
          <div className="result-card-title" style={{ marginTop: 5 }}>{result.title}</div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4, flexShrink: 0 }}>
          {result.sourceCount > 1 && <span className="badge badge-green">{result.sourceCount} źródeł</span>}
        </div>
      </div>
      <div className="result-card-meta">
        <span>{result.sourceId}</span>
        <span>·</span>
        <span style={{ fontStyle: "italic" }}>{resultReason(result)}</span>
      </div>
    </div>
  );
}
