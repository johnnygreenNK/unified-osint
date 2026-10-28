-- UnifiedOSINT - migracja 0003: rejestr zrodel i ich mozliwosci.
-- Tresc tabeli NIE zawiera sekretow - klucze API zyja wylacznie w env.
-- Kolumna `config` moze zawierac nazwy zmiennych wymaganych, limity, timeouty - nigdy wartosci.

create table if not exists sources (
  id text primary key, -- slug, np. 'snusbase', 'dns', 'demo'
  name text not null,
  category text not null check (category in (
    'demo', 'dns_infra', 'certificate_transparency', 'web_archive',
    'breach_data', 'username_recon', 'threat_intel', 'code_repository',
    'social_official_api', 'messaging', 'local_import'
  )),
  status text not null default 'not_configured' check (status in (
    'active', 'disabled', 'not_configured', 'degraded', 'error'
  )),
  adapter_version text not null default '0.1.0',
  required_env_vars text[] not null default '{}',
  config jsonb not null default '{}',
  limits jsonb not null default '{}',
  cost_info jsonb not null default '{}',
  last_ok_at timestamptz,
  last_error_code text,
  last_error_message text,
  updated_at timestamptz not null default now()
);

alter table sources enable row level security;
alter table sources force row level security;

-- Status zrodel jest widoczny dla kazdego zalogowanego - to nie sa dane prywatne.
create policy sources_select on sources for select
  using (app_current_role() in ('admin', 'analyst', 'viewer', 'service'));

create policy sources_write on sources for all
  using (app_is_privileged())
  with check (app_is_privileged());

-- ---------------------------------------------------------------------------
create table if not exists source_capabilities (
  source_id text not null references sources (id) on delete cascade,
  query_type text not null check (query_type in (
    'email', 'username', 'name', 'domain', 'ip', 'phone', 'hash', 'url', 'text'
  )),
  supports_wildcards boolean not null default false,
  max_results int not null default 50,
  primary key (source_id, query_type)
);

alter table source_capabilities enable row level security;
alter table source_capabilities force row level security;

create policy source_capabilities_select on source_capabilities for select
  using (app_current_role() in ('admin', 'analyst', 'viewer', 'service'));

create policy source_capabilities_write on source_capabilities for all
  using (app_is_privileged())
  with check (app_is_privileged());
