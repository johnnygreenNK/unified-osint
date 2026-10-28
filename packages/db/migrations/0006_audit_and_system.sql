-- UnifiedOSINT - migracja 0006: audyt (append-only), limity, cache, dedup webhookow.

create table if not exists audit_logs (
  id bigserial primary key,
  actor_id uuid references users (id) on delete set null,
  action text not null,
  target text,
  meta jsonb not null default '{}',
  ip_hash text,
  created_at timestamptz not null default now()
);

alter table audit_logs enable row level security;
alter table audit_logs force row level security;

-- Tylko SELECT (admin) i INSERT (service) sa zdefiniowane - brak polityk
-- UPDATE/DELETE oznacza, ze FORCE ROW LEVEL SECURITY blokuje je dla wszystkich,
-- wlacznie z wlascicielem tabeli. Audyt jest append-only.
create policy audit_logs_select on audit_logs for select
  using (app_current_role() in ('admin', 'service'));

create policy audit_logs_insert on audit_logs for insert
  with check (app_current_role() = 'service' or app_is_privileged());

create index if not exists idx_audit_logs_created on audit_logs (created_at desc);
create index if not exists idx_audit_logs_actor on audit_logs (actor_id);

-- ---------------------------------------------------------------------------
-- Tabele czysto backendowe - zero dostepu z poziomu uzytkownika (tylko 'service').
create table if not exists rate_limit_counters (
  subject text not null,
  window_start timestamptz not null,
  count int not null default 0,
  primary key (subject, window_start)
);

alter table rate_limit_counters enable row level security;
alter table rate_limit_counters force row level security;

create policy rate_limit_counters_service on rate_limit_counters for all
  using (app_current_role() = 'service')
  with check (app_current_role() = 'service');

-- ---------------------------------------------------------------------------
create table if not exists cache_entries (
  key_hash text primary key,
  owner_id uuid,
  payload jsonb not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

alter table cache_entries enable row level security;
alter table cache_entries force row level security;

create policy cache_entries_service on cache_entries for all
  using (app_current_role() = 'service')
  with check (app_current_role() = 'service');

create index if not exists idx_cache_entries_expires on cache_entries (expires_at);

-- ---------------------------------------------------------------------------
-- Dedup webhookow Telegrama (ten sam update_id moze przyjsc wielokrotnie).
create table if not exists telegram_webhook_updates (
  update_id bigint primary key,
  received_at timestamptz not null default now()
);

alter table telegram_webhook_updates enable row level security;
alter table telegram_webhook_updates force row level security;

create policy telegram_webhook_updates_service on telegram_webhook_updates for all
  using (app_current_role() = 'service')
  with check (app_current_role() = 'service');
