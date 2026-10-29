-- UnifiedOSINT - migracja 0009: wlasne importy danych (CSV/SQL dump).
-- Uzytkownik moze wgrac wlasny plik (np. wyciek znaleziony samemu) - wiersze
-- trafiaja tutaj z wyodrebnionymi polami korelacji, a adapter 'local_import'
-- (packages/adapters/src/localImport.ts) przeszukuje je jak kazde inne
-- zrodlo, wiec wynik przechodzi przez ten sam pipeline dedupu/maskowania/SSE.

create table if not exists import_batches (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references users (id) on delete cascade,
  filename text not null,
  format text not null check (format in ('csv', 'sql')),
  row_count int not null default 0,
  skipped_count int not null default 0,
  created_at timestamptz not null default now()
);

alter table import_batches enable row level security;
alter table import_batches force row level security;

create policy import_batches_select on import_batches for select
  using (owner_id = app_current_user_id() or app_is_privileged());

create policy import_batches_insert on import_batches for insert
  with check (owner_id = app_current_user_id() or app_current_role() = 'service');

create index if not exists idx_import_batches_owner on import_batches (owner_id, created_at desc);

-- ---------------------------------------------------------------------------
create table if not exists local_import_records (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references users (id) on delete cascade,
  batch_id uuid not null references import_batches (id) on delete cascade,
  email text,
  username text,
  ip text,
  phone text,
  domain text,
  attrs jsonb not null default '{}',
  created_at timestamptz not null default now()
);

alter table local_import_records enable row level security;
alter table local_import_records force row level security;

create policy local_import_records_select on local_import_records for select
  using (owner_id = app_current_user_id() or app_is_privileged());

create policy local_import_records_insert on local_import_records for insert
  with check (owner_id = app_current_user_id() or app_current_role() = 'service');

-- Indeksy czesciowe per pole korelacji - zapytanie adaptera filtruje zawsze
-- po owner_id i jednym konkretnym polu (zgodnie z query.type), nigdy po wszystkich naraz.
create index if not exists idx_local_import_email on local_import_records (owner_id, email) where email is not null;
create index if not exists idx_local_import_username on local_import_records (owner_id, username) where username is not null;
create index if not exists idx_local_import_ip on local_import_records (owner_id, ip) where ip is not null;
create index if not exists idx_local_import_phone on local_import_records (owner_id, phone) where phone is not null;
create index if not exists idx_local_import_domain on local_import_records (owner_id, domain) where domain is not null;
