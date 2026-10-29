/**
 * Klient wewnetrznego REST API (apps/api) dla bota Telegram. Bot loguje sie
 * tym samym mechanizmem co panel web (POST /auth/auto-login - dziala tylko
 * w trybie jednego konta, patrz ensureDefaultUser.ts) i trzyma ciasteczka
 * sesji recznie (serwerowy fetch nie ma wbudowanego cookie jar jak przegladarka).
 */

export interface StartSearchResult {
  searchId: string;
  correlationId: string;
  sourceIds: string[];
  skippedSourceIds: { sourceId: string; reason: string }[];
}

export interface SseEvent {
  id: string;
  type: string;
  payload: Record<string, unknown>;
}

export interface CanonicalRecordDetail {
  id: string;
  kind: string;
  title: string;
  summary: string | null;
  attrs: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
  source_count: number;
  sourceRecords: Array<{
    id: string;
    sourceId: string;
    sourceRecordId: string;
    urlCanonical: string | null;
    observedAt: string;
    raw: Record<string, unknown>;
  }>;
}

export class ApiClient {
  private cookie = "";

  constructor(private readonly baseUrl: string) {}

  private async request<T>(path: string, init?: RequestInit, retryOn401 = true): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", Cookie: this.cookie, ...init?.headers },
    });
    this.captureCookies(res);

    if (res.status === 401 && retryOn401) {
      await this.autoLogin();
      return this.request<T>(path, init, false);
    }
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`API ${path} -> HTTP ${res.status}: ${body.slice(0, 300)}`);
    }
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }

  private captureCookies(res: Response): void {
    const setCookie =
      typeof (res.headers as { getSetCookie?: () => string[] }).getSetCookie === "function"
        ? (res.headers as unknown as { getSetCookie: () => string[] }).getSetCookie()
        : [];
    if (setCookie.length === 0) return;
    const jar = new Map<string, string>();
    for (const part of this.cookie.split("; ").filter(Boolean)) {
      const [k, v] = part.split("=");
      if (k) jar.set(k, v ?? "");
    }
    for (const raw of setCookie) {
      const [pair] = raw.split(";");
      const [k, v] = (pair ?? "").split("=");
      if (k) jar.set(k.trim(), v ?? "");
    }
    this.cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  async autoLogin(): Promise<void> {
    await this.request("/auth/auto-login", { method: "POST", body: "{}" }, false);
  }

  async startSearch(query: string): Promise<StartSearchResult> {
    return this.request<StartSearchResult>("/searches", { method: "POST", body: JSON.stringify({ query }) });
  }

  async fetchCanonicalRecord(id: string): Promise<CanonicalRecordDetail> {
    return this.request<CanonicalRecordDetail>(`/canonical-records/${id}`);
  }

  /**
   * Konsumuje `GET /searches/:id/events` (text/event-stream). Fastify nie
   * jest serwerem HTTP/2 wiec kazde zdarzenie to blok rozdzielony pusta
   * linia; parsujemy go recznie (Node fetch zwraca web ReadableStream, nie
   * ma wbudowanego EventSource po stronie serwera).
   */
  async streamSearchEvents(
    searchId: string,
    onEvent: (ev: SseEvent) => void,
    opts: { timeoutMs: number }
  ): Promise<void> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs);
    try {
      const res = await fetch(`${this.baseUrl}/searches/${searchId}/events`, {
        headers: { Cookie: this.cookie },
        signal: controller.signal,
      });
      if (!res.ok || !res.body) throw new Error(`SSE ${searchId} -> HTTP ${res.status}`);

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let done = false;
      while (!done) {
        const chunk = await reader.read();
        done = chunk.done;
        if (chunk.value) buffer += decoder.decode(chunk.value, { stream: true });

        let sepIndex: number;
        while ((sepIndex = buffer.indexOf("\n\n")) !== -1) {
          const block = buffer.slice(0, sepIndex);
          buffer = buffer.slice(sepIndex + 2);
          const parsed = parseSseBlock(block);
          if (parsed) {
            onEvent(parsed);
            if (parsed.type === "search.completed") return;
          }
        }
      }
    } finally {
      clearTimeout(timer);
    }
  }
}

function parseSseBlock(block: string): SseEvent | null {
  let id = "";
  let type = "";
  let data = "";
  for (const line of block.split("\n")) {
    if (line.startsWith("id: ")) id = line.slice(4);
    else if (line.startsWith("event: ")) type = line.slice(7);
    else if (line.startsWith("data: ")) data = line.slice(6);
  }
  if (!type || !data) return null;
  try {
    return { id, type, payload: JSON.parse(data) as Record<string, unknown> };
  } catch {
    return null;
  }
}
