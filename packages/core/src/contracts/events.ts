/**
 * Typy zdarzen zapisywanych w tabeli `search_events` i wysylanych przez SSE.
 * Payload musi byc mały i NIE moze zawierac sekretow ani surowych danych
 * zrodlowych w pelnej postaci (patrz dokumentacja SSE w docs/live-search.md).
 */
export const SEARCH_EVENT_TYPES = [
  "search.started",
  "task.status",
  "result.added",
  "result.merged",
  "task.error",
  "heartbeat",
  "search.completed",
] as const;
export type SearchEventType = (typeof SEARCH_EVENT_TYPES)[number];

export const TASK_STATUSES = [
  "pending",
  "running",
  "succeeded",
  "failed",
  "cancelled",
  "skipped",
] as const;
export type TaskStatus = (typeof TASK_STATUSES)[number];

export interface SearchStartedPayload {
  searchId: string;
  sourceIds: string[];
  queryType: string;
}

export interface TaskStatusPayload {
  taskId: string;
  sourceId: string;
  status: TaskStatus;
  latencyMs: number | null;
  resultCount: number;
  errorCode: string | null;
}

export interface ResultAddedPayload {
  canonicalRecordId: string;
  sourceId: string;
  kind: string;
  title: string;
  sourceCount: number;
}

export interface ResultMergedPayload {
  canonicalRecordId: string;
  sourceId: string;
  sourceCount: number;
}

export interface TaskErrorPayload {
  taskId: string;
  sourceId: string;
  errorCode: string;
  message: string;
  retryable: boolean;
}

export interface SearchCompletedPayload {
  searchId: string;
  partial: boolean;
  totalResults: number;
  totalDuplicates: number;
  durationMs: number;
}

export type SearchEventPayload =
  | SearchStartedPayload
  | TaskStatusPayload
  | ResultAddedPayload
  | ResultMergedPayload
  | TaskErrorPayload
  | SearchCompletedPayload
  | Record<string, never>;

export interface SearchEvent<T extends SearchEventPayload = SearchEventPayload> {
  id: string;
  searchId: string;
  type: SearchEventType;
  payload: T;
  createdAt: string;
}
