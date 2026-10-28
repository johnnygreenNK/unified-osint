-- UnifiedOSINT - migracja 0004: wyszukiwania, zadania per zrodlo, zdarzenia live.
-- Retencja (do wdrozenia jako cron w Etapie 10): searches/search_tasks 90 dni,
-- search_events 7 dni - dokumentacja w docs/runbook.md.

create table if not exists searches (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users (id) on delete cascade,
  query_raw text not null,
  query_type text not null check (query_type in (
    'email', 'username', 'name', 'domain', 'ip', 'phone', 'hash', 'url', 'text'
  )),
  query_norm text not null,
  has_wildcards boolean not null default false,
  scope text not null default 'user' check (scope in ('user', 'team')),
  source_ids text[] not null,
  status text not null default 'pending' check (status in ('pending', 'running', 'completed', 'cancelled')),
  partial boolean not null default false,
  correlation_id uuid not null default gen_random_uuid(),
  norm_version int not null,
  created_at timestamptz not null default now(),
  started_at timestamptz,
  completed_at timestamptz
);

alter table searches enable row level security;
alter table searches force row level security;

create policy searches_select on searches for select
  using (user_id = app_current_user_id() or app_is_privileged());

create policy searches_insert on searches for insert
  with check (user_id = app_current_user_id() or app_current_role() = 'service');

create policy searches_update on searches for update
  using (user_id = app_current_user_id() or app_is_privileged())
  with check (user_id = app_current_user_id() or app_is_privileged());

create index if not exists idx_searches_user_created on searches (user_id, created_at desc);
create index if not exists idx_searches_correlation on searches (correlation_id);

-- ---------------------------------------------------------------------------
create table if not exists search_tasks (
  id uuid primary key default gen_random_uuid(),
  search_id uuid not null references searches (id) on delete cascade,
  source_id text not null references sources (id),
  status text not null default 'pending' check (status in (
    'pending', 'running', 'succeeded', 'failed', 'cancelled', 'skipped'
  )),
  attempt int not null default 0,
  error_code text,
  error_message text,
  latency_ms int,
  result_count int not null default 0,
  cost_units numeric not null default 0,
  started_at timestamptz,
  finished_at timestamptz,
  unique (search_id, source_id)
);

alter table search_tasks enable row level security;
alter table search_tasks force row level security;

create policy search_tasks_all on search_tasks for all
  using (
    app_is_privileged()
    or exists (select 1 from searches s where s.id = search_tasks.search_id and s.user_id = app_current_user_id())
  )
  with check (app_current_role() = 'service' or app_is_privileged());

create index if not exists idx_search_tasks_search on search_tasks (search_id);

-- ---------------------------------------------------------------------------
create table if not exists search_events (
  id bigserial primary key,
  search_id uuid not null references searches (id) on delete cascade,
  type text not null check (type in (
    'search.started', 'task.status', 'result.added', 'result.merged',
    'task.error', 'heartbeat', 'search.completed'
  )),
  payload jsonb not null default '{}',
  created_at timestamptz not null default now()
);

alter table search_events enable row level security;
alter table search_events force row level security;

create policy search_events_select on search_events for select
  using (
    app_is_privileged()
    or exists (select 1 from searches s where s.id = search_events.search_id and s.user_id = app_current_user_id())
  );

create policy search_events_insert on search_events for insert
  with check (app_current_role() = 'service' or app_is_privileged());

create index if not exists idx_search_events_search_id on search_events (search_id, id);
