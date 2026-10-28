-- UnifiedOSINT - migracja 0002: uzytkownicy, konta Telegram, parowanie, preferencje.

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  password_hash text not null,
  display_name text not null,
  role text not null default 'viewer' check (role in ('admin', 'analyst', 'viewer')),
  created_at timestamptz not null default now(),
  disabled_at timestamptz
);

alter table users enable row level security;
alter table users force row level security;

-- Wlasny profil widoczny zawsze; admin/service widza wszystkich (panel admina, logowanie).
create policy users_select on users for select
  using (id = app_current_user_id() or app_is_privileged());

-- Rejestracja odbywa sie w kontekscie 'service' (zanim istnieje sesja usera).
create policy users_insert on users for insert
  with check (app_current_role() = 'service');

create policy users_update on users for update
  using (id = app_current_user_id() or app_is_privileged())
  with check (id = app_current_user_id() or app_is_privileged());

create index if not exists idx_users_role on users (role);

-- ---------------------------------------------------------------------------
create table if not exists connected_accounts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users (id) on delete cascade,
  provider text not null check (provider in ('telegram')),
  external_id text not null,
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  unique (provider, external_id)
);

alter table connected_accounts enable row level security;
alter table connected_accounts force row level security;

create policy connected_accounts_all on connected_accounts for all
  using (user_id = app_current_user_id() or app_is_privileged())
  with check (user_id = app_current_user_id() or app_current_role() = 'service');

create index if not exists idx_connected_accounts_user on connected_accounts (user_id);

-- ---------------------------------------------------------------------------
-- Kody parowania Telegrama: generowane w panelu, zuzywane przez bota.
-- Tabela czysto backendowa - widoczna tylko dla kontekstu 'service'.
create table if not exists telegram_pairing_codes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users (id) on delete cascade,
  code_hash text not null unique,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

alter table telegram_pairing_codes enable row level security;
alter table telegram_pairing_codes force row level security;

create policy telegram_pairing_codes_service on telegram_pairing_codes for all
  using (app_current_role() = 'service')
  with check (app_current_role() = 'service');

create index if not exists idx_pairing_codes_expires on telegram_pairing_codes (expires_at);

-- ---------------------------------------------------------------------------
create table if not exists user_preferences (
  user_id uuid primary key references users (id) on delete cascade,
  default_sources text[] not null default '{}',
  telegram_notify boolean not null default true,
  updated_at timestamptz not null default now()
);

alter table user_preferences enable row level security;
alter table user_preferences force row level security;

create policy user_preferences_owner on user_preferences for all
  using (user_id = app_current_user_id() or app_is_privileged())
  with check (user_id = app_current_user_id() or app_current_role() = 'service');
