-- UnifiedOSINT - migracja 0005: rekordy kanoniczne, rekordy zrodlowe, agregacja, fingerprinty.
-- owner_scope='user' w MVP (owner_id = users.id). owner_scope='team' zarezerwowane na v2.

create table if not exists canonical_records (
  id uuid primary key default gen_random_uuid(),
  owner_scope text not null default 'user' check (owner_scope in ('user', 'team')),
  owner_id uuid not null,
  kind text not null,
  canonical_key text not null,
  title text not null,
  summary text,
  attrs jsonb not null default '{}',
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  source_count int not null default 1,
  norm_version int not null,
  created_at timestamptz not null default now(),
  unique (owner_scope, owner_id, kind, canonical_key)
);

alter table canonical_records enable row level security;
alter table canonical_records force row level security;

create policy canonical_records_all on canonical_records for all
  using (
    app_is_privileged()
    or (owner_scope = 'user' and owner_id = app_current_user_id())
  )
  with check (
    app_current_role() = 'service'
    or (owner_scope = 'user' and owner_id = app_current_user_id())
  );

create index if not exists idx_canonical_records_owner on canonical_records (owner_scope, owner_id, kind);

-- ---------------------------------------------------------------------------
create table if not exists source_records (
  id uuid primary key default gen_random_uuid(),
  owner_scope text not null default 'user' check (owner_scope in ('user', 'team')),
  owner_id uuid not null,
  source_id text not null references sources (id),
  source_record_id text not null,
  search_id uuid references searches (id) on delete set null,
  url_canonical text,
  raw_hash text not null,
  raw jsonb,
  observed_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  unique (owner_scope, owner_id, source_id, source_record_id)
);

alter table source_records enable row level security;
alter table source_records force row level security;

create policy source_records_all on source_records for all
  using (
    app_is_privileged()
    or (owner_scope = 'user' and owner_id = app_current_user_id())
  )
  with check (
    app_current_role() = 'service'
    or (owner_scope = 'user' and owner_id = app_current_user_id())
  );

create index if not exists idx_source_records_owner on source_records (owner_scope, owner_id, source_id);
create index if not exists idx_source_records_search on source_records (search_id);

-- ---------------------------------------------------------------------------
create table if not exists record_sources (
  canonical_id uuid not null references canonical_records (id) on delete cascade,
  source_record_id uuid not null references source_records (id) on delete cascade,
  link_type text not null check (link_type in ('same', 'similar')),
  confidence numeric,
  observed_at timestamptz not null default now(),
  primary key (canonical_id, source_record_id)
);

alter table record_sources enable row level security;
alter table record_sources force row level security;

create policy record_sources_all on record_sources for all
  using (
    app_is_privileged()
    or exists (
      select 1 from canonical_records c
      where c.id = record_sources.canonical_id and c.owner_scope = 'user' and c.owner_id = app_current_user_id()
    )
  )
  with check (app_current_role() = 'service' or app_is_privileged());

-- ---------------------------------------------------------------------------
create table if not exists record_fingerprints (
  id uuid primary key default gen_random_uuid(),
  canonical_id uuid not null references canonical_records (id) on delete cascade,
  owner_scope text not null default 'user' check (owner_scope in ('user', 'team')),
  owner_id uuid not null,
  fp_type text not null check (fp_type in ('id', 'url', 'content', 'simhash')),
  fp_value text not null,
  norm_version int not null,
  created_at timestamptz not null default now(),
  unique (owner_scope, owner_id, fp_type, fp_value, norm_version)
);

alter table record_fingerprints enable row level security;
alter table record_fingerprints force row level security;

create policy record_fingerprints_all on record_fingerprints for all
  using (
    app_is_privileged()
    or (owner_scope = 'user' and owner_id = app_current_user_id())
  )
  with check (
    app_current_role() = 'service'
    or (owner_scope = 'user' and owner_id = app_current_user_id())
  );

create index if not exists idx_record_fingerprints_lookup on record_fingerprints (owner_scope, owner_id, fp_type, fp_value, norm_version);
