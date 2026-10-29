"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  API_BASE_URL,
  ApiError,
  fetchMe,
  fetchSources,
  logout,
  startSearch,
  type SessionUser,
  type SourceInfo,
} from "@/lib/api";
import { RelatedRecordsPanel } from "@/components/RelatedRecordsPanel";

const QUERY_TYPES = ["", "email", "username", "name", "domain", "ip", "phone", "hash", "url", "text"] as const;

interface LiveEvent {
  id: string;
  type: string;
  payload: Record<string, unknown>;
}

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser] = useState<SessionUser | null>(null);
  const [sources, setSources] = useState<SourceInfo[]>([]);
  const [selectedSources, setSelectedSources] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [queryType, setQueryType] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [searchId, setSearchId] = useState<string | null>(null);
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [skipped, setSkipped] = useState<{ sourceId: string; reason: string }[]>([]);
  const eventSourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    fetchMe()
      .then(setUser)
      .catch(() => router.push("/"));
    fetchSources()
      .then((res) => setSources(res.sources))
      .catch(() => {});
  }, [router]);

  useEffect(() => {
    return () => {
      eventSourceRef.current?.close();
    };
  }, []);

  function toggleSource(id: string): void {
    setSelectedSources((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function onSearchSubmit(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    setError(null);
    setBusy(true);
    setEvents([]);
    setSkipped([]);
    eventSourceRef.current?.close();

    try {
      const result = await startSearch(
        query,
        queryType || undefined,
        selectedSources.size > 0 ? [...selectedSources] : undefined
      );
      setSearchId(result.searchId);
      setSkipped(result.skippedSourceIds);

      const es = new EventSource(`${API_BASE_URL}/searches/${result.searchId}/events`, { withCredentials: true });
      eventSourceRef.current = es;
      const handler = (type: string) => (ev: MessageEvent) => {
        setEvents((prev) => [...prev, { id: ev.lastEventId, type, payload: JSON.parse(ev.data) }]);
      };
      for (const type of ["search.started", "task.status", "result.added", "result.merged", "task.error", "search.completed"]) {
        es.addEventListener(type, handler(type));
      }
      es.onerror = () => {
        // EventSource auto-reconnects; serwer wysyla Last-Event-ID replay, wiec nic nie gubimy.
      };
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Nie udalo sie uruchomic wyszukiwania");
    } finally {
      setBusy(false);
    }
  }

  async function onLogout(): Promise<void> {
    await logout();
    router.push("/");
  }

  if (!user) return <div className="container">Ladowanie...</div>;

  return (
    <div className="container">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h1>UnifiedOSINT</h1>
        <div>
          <span className="muted">
            {user.displayName} ({user.role})
          </span>{" "}
          <button className="secondary" onClick={onLogout}>
            Wyloguj
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Nowe wyszukiwanie</h3>
        <form onSubmit={onSearchSubmit} className="row" style={{ flexDirection: "column", alignItems: "stretch" }}>
          <input
            type="text"
            placeholder="np. jan.kowalski@example.com albo jan*.kowalski@example.com"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            required
          />
          <select value={queryType} onChange={(e) => setQueryType(e.target.value)}>
            {QUERY_TYPES.map((t) => (
              <option key={t} value={t}>
                {t === "" ? "wykryj automatycznie" : t}
              </option>
            ))}
          </select>

          <div>
            <div className="muted" style={{ marginBottom: 6 }}>
              Zrodla (brak wyboru = wszystkie dostepne):
            </div>
            <div className="row">
              {sources.map((s) => (
                <label key={s.id} className="badge" style={{ cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={selectedSources.has(s.id)}
                    onChange={() => toggleSource(s.id)}
                    style={{ marginRight: 4 }}
                  />
                  {s.name} · {s.status}
                </label>
              ))}
            </div>
          </div>

          {error && <div className="error">{error}</div>}
          <button type="submit" disabled={busy}>
            Szukaj
          </button>
        </form>
      </div>

      {searchId && (
        <div className="card">
          <h3>Wyniki (search_id: {searchId})</h3>
          {skipped.length > 0 && (
            <p className="muted">
              Pominięte zrodla: {skipped.map((s) => `${s.sourceId} (${s.reason})`).join(", ")}
            </p>
          )}
          {events.length === 0 && <p className="muted">Czekam na pierwsze wyniki...</p>}
          {events.map((ev, i) => {
            const canonicalRecordId =
              (ev.type === "result.added" || ev.type === "result.merged") &&
              typeof ev.payload.canonicalRecordId === "string"
                ? ev.payload.canonicalRecordId
                : null;
            return (
              <div key={i} className="result-item">
                <span className="badge">{ev.type}</span>{" "}
                <code style={{ fontSize: 12 }}>{JSON.stringify(ev.payload)}</code>
                {canonicalRecordId && <RelatedRecordsPanel canonicalRecordId={canonicalRecordId} />}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
