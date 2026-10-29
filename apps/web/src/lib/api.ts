export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";

export interface SessionUser {
  id: string;
  email: string;
  displayName: string;
  role: "admin" | "analyst" | "viewer";
}

export interface ApiErrorBody {
  error: string;
  message?: string;
}

export class ApiError extends Error {
  constructor(public readonly status: number, public readonly body: ApiErrorBody) {
    super(body.message ?? body.error);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    credentials: "include",
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!res.ok) {
    const body = (await res.json().catch(() => ({ error: "unknown_error" }))) as ApiErrorBody;
    throw new ApiError(res.status, body);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export function login(email: string, password: string): Promise<SessionUser> {
  return request<SessionUser>("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
}

export function register(email: string, password: string, displayName: string): Promise<SessionUser> {
  return request<SessionUser>("/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password, displayName }),
  });
}

export function logout(): Promise<{ ok: true }> {
  return request("/auth/logout", { method: "POST" });
}

export function fetchMe(): Promise<SessionUser> {
  return request<SessionUser>("/auth/me");
}

export interface SourceInfo {
  id: string;
  name: string;
  category: string;
  status: string;
  adapter_version: string;
  last_ok_at: string | null;
  last_error_code: string | null;
}

export function fetchSources(): Promise<{ sources: SourceInfo[] }> {
  return request("/sources");
}

export interface StartSearchResult {
  searchId: string;
  correlationId: string;
  sourceIds: string[];
  skippedSourceIds: { sourceId: string; reason: string }[];
}

export function startSearch(query: string, queryType?: string, sourceIds?: string[]): Promise<StartSearchResult> {
  return request<StartSearchResult>("/searches", {
    method: "POST",
    body: JSON.stringify({ query, queryType, sourceIds }),
  });
}

export function cancelSearch(searchId: string): Promise<{ ok: true }> {
  return request(`/searches/${searchId}/cancel`, { method: "POST" });
}

export interface RelatedRecord {
  id: string;
  kind: string;
  title: string;
  summary: string | null;
  first_seen: string;
  last_seen: string;
  source_count: number;
  shared_keys: string[];
}

export function fetchRelatedRecords(canonicalRecordId: string): Promise<{ related: RelatedRecord[] }> {
  return request(`/canonical-records/${canonicalRecordId}/related`);
}
