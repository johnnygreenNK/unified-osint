-- UnifiedOSINT - migracja 0008: klucze korelacji tozsamosci miedzy rekordami kanonicznymi.
--
-- Cel: po znalezieniu jednej osoby (np. po e-mailu) pokazac inne rekordy
-- kanoniczne tego samego wlasciciela, ktore dziela wspolny atrybut silnie
-- identyfikujacy (ten sam e-mail/username/IP/telefon/domena), nawet jesli
-- pochodza z innego zrodla lub innego zapytania. To ODREBNA warstwa od
-- dedupu (record_fingerprints) - fingerprinty laczy IDENTYCZNY rekord,
-- korelacja laczy ROZNE rekordy o wspolnym atrybucie (np. dwa konta
-- e-mail zalogowane z tego samego IP). Nigdy automatyczne scalenie
-- rekordow kanonicznych - tylko sugestia widoczna w UI.

create table if not exists record_correlation_keys (
  id uuid primary key default gen_random_uuid(),
  canonical_id uuid not null references canonical_records (id) on delete cascade,
  owner_scope text not null default 'user' check (owner_scope in ('user', 'team')),
  owner_id uuid not null,
  key_type text not null check (key_type in ('email', 'username', 'ip', 'phone', 'domain')),
  key_value text not null,
  created_at timestamptz not null default now(),
  unique (owner_scope, owner_id, canonical_id, key_type, key_value)
);

alter table record_correlation_keys enable row level security;
alter table record_correlation_keys force row level security;

create policy record_correlation_keys_all on record_correlation_keys for all
  using (
    app_is_privileged()
    or (owner_scope = 'user' and owner_id = app_current_user_id())
  )
  with check (
    app_current_role() = 'service'
    or app_is_privileged()
    or (owner_scope = 'user' and owner_id = app_current_user_id())
  );

-- Lookup "kto inny dzieli ten klucz" - rdzen zapytania /canonical-records/:id/related.
create index if not exists idx_record_correlation_keys_lookup
  on record_correlation_keys (owner_scope, owner_id, key_type, key_value);

create index if not exists idx_record_correlation_keys_canonical
  on record_correlation_keys (canonical_id);
