-- UnifiedOSINT - migracja 0001: rozszerzenia i funkcje pomocnicze dla RLS.
--
-- Bez Supabase: autoryzacja wlasna. Kazde polaczenie backendu wykonuje na
-- poczatku transakcji:
--   SET LOCAL app.user_id = '<uuid>';
--   SET LOCAL app.role    = '<admin|analyst|viewer|service>';
-- Rola 'service' to zaufany kontekst backendu (rejestracja, logowanie,
-- joby systemowe) - polityki RLS jawnie dopuszczaja ten kontekst tam,
-- gdzie nie ma jeszcze zalogowanego uzytkownika.
--
-- WAZNE: wszystkie tabele z danymi uzytkownika dostaja
-- `FORCE ROW LEVEL SECURITY`, bo proces aplikacji laczy sie jako wlasciciel
-- tabel (osint_app) - bez FORCE wlasciciel obchodzi RLS.

create extension if not exists pgcrypto;

create or replace function app_current_user_id() returns uuid as $$
  select nullif(current_setting('app.user_id', true), '')::uuid
$$ language sql stable;

create or replace function app_current_role() returns text as $$
  select coalesce(current_setting('app.role', true), '')
$$ language sql stable;

create or replace function app_is_privileged() returns boolean as $$
  select app_current_role() in ('admin', 'service')
$$ language sql stable;

create table if not exists _migrations (
  id text primary key,
  applied_at timestamptz not null default now()
);
