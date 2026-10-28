-- UnifiedOSINT - migracja 0007: naprawa polityki RLS na record_sources.
--
-- Blad: `record_sources_all.with check` wymagal roli service/privileged do
-- zapisu, podczas gdy `upsertNormalizedRecord()` (packages/core/src/dedup/
-- dedupEngine.ts) wstawia do record_sources w ramach tej samej transakcji
-- co canonical_records/source_records/record_fingerprints - a te trzy
-- tabele poprawnie pozwalaja wlascicielowi (owner_id = app_current_user_id())
-- zapisywac wlasne rekordy. Efekt: kazde wyszukiwanie zwracajace jakikolwiek
-- wynik konczylo sie bledem RLS ("nowy wiersz narusza polityke bezpieczenstwa
-- na poziomie wierszy tabeli record_sources") dla zwyklego uzytkownika
-- (rola viewer), bo dedup dziala w kontekscie uzytkownika, nie serwisu.
--
-- Naprawa: with check dla record_sources dostaje ten sam warunek wlasnosci
-- co using - zgodnie z wzorcem uzytym w pozostalych trzech tabelach rekordow.

drop policy if exists record_sources_all on record_sources;

create policy record_sources_all on record_sources for all
  using (
    app_is_privileged()
    or exists (
      select 1 from canonical_records c
      where c.id = record_sources.canonical_id and c.owner_scope = 'user' and c.owner_id = app_current_user_id()
    )
  )
  with check (
    app_current_role() = 'service'
    or app_is_privileged()
    or exists (
      select 1 from canonical_records c
      where c.id = record_sources.canonical_id and c.owner_scope = 'user' and c.owner_id = app_current_user_id()
    )
  );
