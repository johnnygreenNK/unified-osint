export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "/api";

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

async function rawFetch(path: string, init?: RequestInit): Promise<Response> {
  return fetch(`${API_BASE_URL}${path}`, {
    ...init,
    credentials: "include",
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res = await rawFetch(path, init);
  // Token dostepu wygasa - odnow sesje (auto-login) i powtorz zapytanie raz.
  if (res.status === 401 && !path.startsWith("/auth/")) {
    const relog = await rawFetch("/auth/auto-login", { method: "POST", body: "{}" });
    if (relog.ok) res = await rawFetch(path, init);
  }
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

export function autoLogin(): Promise<SessionUser> {
  return request<SessionUser>("/auth/auto-login", { method: "POST", body: "{}" });
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
  queryTypes: string[];
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

export interface SourceRecordMeta {
  id: string;
  sourceId: string;
  sourceRecordId: string;
  urlCanonical: string | null;
  observedAt: string;
  raw: Record<string, unknown>;
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
  sourceRecords: SourceRecordMeta[];
}

export function fetchCanonicalRecord(id: string): Promise<CanonicalRecordDetail> {
  return request<CanonicalRecordDetail>(`/canonical-records/${id}`);
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

export function revealField(sourceRecordId: string, field: string): Promise<{ value: string | null }> {
  return request(`/source-records/${sourceRecordId}/reveal`, {
    method: "POST",
    body: JSON.stringify({ field }),
  });
}

export interface ImportBatchResult {
  batchId: string;
  filename: string;
  format: "csv" | "sql";
  rowCount: number;
  skippedCount: number;
}

export interface ImportBatchSummary {
  id: string;
  filename: string;
  format: "csv" | "sql";
  row_count: number;
  skipped_count: number;
  created_at: string;
}

export async function uploadImport(file: File): Promise<ImportBatchResult> {
  const formData = new FormData();
  formData.append("file", file);
  const res = await fetch(`${API_BASE_URL}/imports`, {
    method: "POST",
    credentials: "include",
    body: formData,
  });
  if (!res.ok) {
    const body = (await res.json().catch(() => ({ error: "unknown_error" }))) as ApiErrorBody;
    throw new ApiError(res.status, body);
  }
  return (await res.json()) as ImportBatchResult;
}

export function fetchImportBatches(): Promise<{ batches: ImportBatchSummary[] }> {
  return request("/imports");
}
