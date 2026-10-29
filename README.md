# UnifiedOSINT

Modularna platforma OSINT (panel WWW + API + worker) łącząca wiele źródeł
wywiadu w jednym miejscu: strumieniowane na żywo (SSE) wyniki wyszukiwania,
deduplikacja wielowarstwowa z zachowaniem pochodzenia danych, włączanie/wyłączanie
źródeł per wyszukiwanie, system uprawnień z audytem, monitoring zdrowia
adapterów. **Wyłącznie legalny OSINT** — żadnego przełamywania zabezpieczeń,
CAPTCHA, paywalli ani nieautoryzowanego dostępu.

## Architektura

Monorepo pnpm (workspaces: `apps/*`, `packages/*`):

- [apps/web](apps/web) — panel WWW (Next.js, App Router)
- [apps/api](apps/api) — API (Fastify): auth, REST, SSE
- [apps/worker](apps/worker) — worker zadań wyszukiwania (pg-boss)
- [packages/core](packages/core) — kontrakty, orkiestrator, dedup, bezpieczny fetch, RLS helpers
- [packages/adapters](packages/adapters) — adaptery źródeł (demo, dns, snusbase,
  HIBP, LeakCheck.io, Hudson Rock, stuby intelx/epieos/dehashed/spycloud/flare/
  kela/constella, adaptery CLI: amass, trufflehog, gitleaks, sherlock,
  maigret, holehe, theHarvester)
- [packages/db](packages/db) — migracje SQL + runner migracji

Własny Postgres 16 (bez Supabase). Autoryzacja: e-mail + hasło (argon2id),
JWT dostępowy/odświeżający w httpOnly cookies. Row-Level Security wymuszana
przez zmienne sesji Postgresa (`SET LOCAL app.user_id` / `app.role`),
ustawiane wyłącznie przez `withAppContext()` — nigdy ręcznie w zapytaniach.

### Co jest naprawdę zaimplementowane, a co nie

- Działające adaptery: `demo` (dane testowe, oznaczone w UI), `dns`,
  `snusbase` (realne API, aktywny tylko gdy `SNUSBASE_API_KEY` ustawiony
  w `.env` — bez klucza wraca do `not_configured`, zwracając jawny status,
  nie fałszywe wyniki).
- Dodatkowe działające adaptery breach-data (oficjalne, publicznie
  udokumentowane API, aktywne tylko gdy ustawiony odpowiedni klucz —
  bez klucza `not_configured`):
  - `hibp` — Have I Been Pwned API v3 (`HIBP_API_KEY`). Sprawdza e-mail
    pod kątem wycieków (`/breachedaccount`) i wklejek (`/pasteaccount`).
    Źródło: https://haveibeenpwned.com/API/v3
  - `leakcheck` — LeakCheck.io API Pro v2 (`LEAKCHECK_API_KEY`).
    Sprawdza `email`/`username`/`phone` (typy enterprise-only jak `domain`/
    `hash`/`password` celowo pominięte). Źródło: https://docs.leakcheck.io/
  - `hudsonrock` — Hudson Rock / Cavalier API v3 (`HUDSONROCK_API_KEY`).
    Wyszukiwanie infekcji infostealer po `email`/`username`
    (`search-by-login`). Pole `password` w `credentials[]` jest maskowane
    tak samo jak w Snusbase. Źródło: https://docs.hudsonrock.com/
- Adaptery bez klucza, aktywne domyślnie (publiczne API, bez limitu
  kluczowego — mogą być wyłączone przez odpowiedni `ADAPTER_*_ENABLED=false`):
  - `crtsh` — crt.sh (Certificate Transparency log search). Zapytanie
    `domain` → `GET https://crt.sh/?q={domain}&output=json`, wynik
    deduplikowany po `id` (crt.sh zwraca jeden wiersz per certyfikat×SAN).
    Źródło: https://crt.sh/ (nieudokumentowane formalnie, ale stabilne i
    powszechnie używane API zweryfikowane na żywo).
  - `rdap` — RDAP (Registration Data Access Protocol, następca WHOIS).
    Zapytania `domain`/`ip` przez bootstrap `https://rdap.org/domain/{d}`
    lub `/ip/{ip}` — `safeFetch` automatycznie obsługuje przekierowania
    do właściwego rejestru. Źródło: https://rdap.org/,
    https://www.rfc-editor.org/rfc/rfc9083
  - `wayback` — Wayback Machine CDX Server API. Zapytania `domain`/`url`
    przez `http://web.archive.org/cdx/search/cdx?url=...&output=json`
    (dla `domain` z `matchType=domain&collapse=urlkey`). Wiersz nagłówka
    JSON parsowany dynamicznie (bez zakładania kolejności pól), zgodnie
    z dokumentacją. Źródło: https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md
  - `shodan_internetdb` — Shodan InternetDB (darmowy, bez klucza, tylko
    użycie niekomercyjne wg ToS Shodana). Zapytanie `ip` →
    `GET https://internetdb.shodan.io/{ip}`; 404 oznacza brak danych
    (nie błąd). Źródło: https://internetdb.shodan.io/
- Adaptery breach/threat-intel z opcjonalnym kluczem:
  - `emailrep` — EmailRep.io (Sublime Security). Zapytanie `email` →
    `GET https://emailrep.io/{email}` z nagłówkami `Key` i `User-Agent`
    (`EMAILREP_API_KEY`, `EMAILREP_USER_AGENT`). Źródło:
    https://docs.sublime.security/reference/emailrep-introduction.
    **Uwaga**: Sublime Security nie wydaje już nowych kluczy EmailRep
    (serwis nie jest już aktywnie rozwijany — działają tylko klucze
    wydane wcześniej; darmowe nieautoryzowane zapytania są wyłączone).
    Bez klucza adapter zostaje w stanie `not_configured` i nie wykonuje
    żadnego wywołania sieciowego.
- `h8mail` — **nie zaimplementowany, decyzja świadoma.** Domyślnie h8mail
  zapytuje Scylla.sh (nieoficjalny agregator wykradzionych danych/zrzutów
  wycieków), co jest objęte projektową zasadą odmowy integrowania
  szarorynkowych/nielegalnych źródeł breach-danych. Wyłączenie Scylli
  (`-sk`) pozostawia h8mail bez użytecznej funkcjonalności bezkluczowej —
  pozostałe jego źródła (HaveIBeenPwned, Hunter.io itd.) są już pokryte
  przez dedykowane adaptery (`hibp`) lub wymagają osobnej decyzji. Temat
  zgłoszony użytkownikowi do decyzji.
- Adaptery w stanie `not_configured` (bez publicznego API / wymagają
  dostępu enterprise): `intelx`, `epieos`. Epieos nie ma publicznej
  dokumentacji API — dostęp jest tylko na zapytanie/enterprise;
  implementacja zablokowana do czasu uzyskania dostępu przez użytkownika.
- Zaślepki `not_configured` dla pozostałych komercyjnych źródeł
  breach/infostealer — brak publicznej, self-serve dokumentacji API
  (sprzedaż tylko B2B/enterprise albo dokumentacja dostępna jedynie po
  zalogowaniu/demo z działem sprzedaży), więc implementacja zablokowana
  zgodnie z zasadą "nie wymyślaj endpointów API": `dehashed` (DeHashed —
  dokumentacja API v2 niedostępna publicznie bez konta), `spycloud`
  (SpyCloud — dostęp enterprise-sales-gated), `flare` (Flare.io —
  dostęp enterprise-sales-gated), `kela` (KELA — dostęp enterprise-sales-
  gated), `constella` (Constella Intelligence — dostęp enterprise-sales-
  gated). Każdy ma odpowiedni `*_API_KEY` w `.env.example` i
  `verificationNote` w [stubs.ts](packages/adapters/src/stubs.ts)
  wyjaśniający, co trzeba zweryfikować przed realną implementacją.
- Snusbase, HIBP, LeakCheck, Hudson Rock: pola wrażliwe wyniku (`password`,
  `pass`, `hash`, `salt`) są domyślnie maskowane w `attrs` (nigdy nie
  trafiają nieprzemaskowane do SSE/UI/Telegrama) — pełna wartość jest
  zapisana tylko w `source_records.raw` (RLS, właściciel rekordu) i
  odsłaniana wyłącznie przez `POST /source-records/:id/reveal` (rola
  `analyst`/`admin`, każde wywołanie logowane w `audit_logs`, append-only).
- **Brak** wyszukiwania po haśle (plaintext/wildcard) w bazach wycieków —
  świadomie poza zakresem (ryzyko nadużycia). Adaptery breach-data
  (Snusbase, HIBP) są ograniczone do sprawdzenia, czy dany `email`/`username`
  wystąpił w wycieku i gdzie.
- **Adaptery CLI (Etap 3), działają natywnie na Windows, bez Docker-sandboxingu**
  — każdy wymaga ręcznej instalacji binarki i wskazania jej ścieżki w `.env`
  (patrz `.env.example`); bez tego status to `not_configured`, zweryfikowane
  end-to-end (rejestr → DB → realne wyszukiwanie przez API/worker):
  - `amass`, `theharvester` — pasywny recon domen/subdomen. Zweryfikowane
    na `example.com`: obie binarki uruchamiają się i parsują wynik poprawnie
    (testy jednostkowe), ale dla tej konkretnej domeny (IANA-reserved, brak
    realnej infrastruktury) zwracają 0 wyników w pełnym budżecie czasu
    (`CLI_ADAPTER_TIMEOUT_MS`, domyślnie 120 s) — potrzebna domena z realnym
    footprintem DNS, aby zobaczyć wyniki.
  - `gitleaks`, `trufflehog` — skan sekretów w repo git (klon + skan).
    Zweryfikowane end-to-end na publicznym testowym repo
    `trufflesecurity/test_keys`: gitleaks znajduje 3 sekrety w ~2 s,
    trufflehog znajduje 8 sekretów w ~65 s. Pełna, nieshaskowana wartość
    sekretu istnieje tylko w `source_records.raw` (ten sam wzorzec co
    Snusbase) — `attrs`/UI/SSE dostają wyłącznie wersję zredagowaną.
  - `sherlock`, `maigret` — wyszukiwanie nazwy użytkownika po publicznych
    profilach. Zweryfikowane na `torvalds`: sherlock 86 trafień w ~49 s,
    maigret 1 potwierdzone trafienie w ~110 s (maigret domyślnie sprawdza
    dużo więcej serwisów niż sherlock, więc przy tym samym budżecie czasu
    zwraca mniej w pełni zweryfikowanych kont).
  - `holehe` — sprawdza istnienie konta po e-mailu przez ~150 przepływów
    "zapomniałem hasła". **Świadomie bez ograniczania funkcjonalności**
    (decyzja użytkownika, mimo ryzyka ToS/wzorca nadużycia) — używać tylko
    do autoryzowanego OSINT. Zweryfikowane end-to-end: 15 trafień w ~12 s.
  - Każdy adapter CLI ma własny budżet czasu `CLI_ADAPTER_TIMEOUT_MS`
    (domyślnie 120 s) ustawiany per-adapter w `registry.ts`, odrębny od
    `DEFAULT_ADAPTER_TIMEOUT_MS` (15 s) używanego przez szybkie adaptery
    HTTP — bez tego rozdzielenia wolne skanowanie (np. pełny klon historii
    git w trufflehog) było ucinane po 15 s, zanim zdążyło zwrócić wynik.
  - **Recon-ng / SpiderFoot — nie zaimplementowane (go/no-go: no-go na
    tym etapie).** Oba to frameworki modułowe (dziesiątki/setki modułów,
    część wymaga własnych kluczy API, SpiderFoot ma też tryb web UI/serwer)
    — integracja 1:1 z kontraktem `SourceAdapter` (jedno zapytanie, jeden
    strumień wyników) wymagałaby wyboru i utrzymania konkretnej podgrupy
    modułów per typ zapytania, a nie prostego wrapera CLI jak pozostałe
    narzędzia. Do rozważenia jako osobny, większy etap (np. tylko wybrane
    moduły pasywne SpiderFoot przez jego REST API), nie jako kolejny prosty
    adapter CLI.

## Wymagania

- Node.js ≥ 20 (zweryfikowano na 22.x), pnpm (`npx -y pnpm@9.12.0 ...`)
- PostgreSQL 16/17 (lokalny serwis lub Docker)
- Opcjonalnie: Docker Desktop z Docker Compose v2 (patrz niżej — na Windows
  bez WSL/VPN bywa zawodny; ścieżka lokalna poniżej jest tą faktycznie
  zweryfikowaną end-to-end na tym repo)

## Szybki start — lokalnie, bez Dockera (zweryfikowana ścieżka)

Wymaga uruchomionego lokalnie PostgreSQL (np. jako usługa Windows) i pliku
`.env` w korzeniu repo z `DATABASE_URL` wskazującym na tę bazę (oraz resztą
zmiennych z `.env.example` — sekrety JWT, `CORS_ALLOWED_ORIGINS` itd.).

```bash
npx -y pnpm@9.12.0 install
npx -y pnpm@9.12.0 run build        # buduje wszystkie pakiety (apps/* -> dist/)
node --env-file=.env packages/db/scripts/migrate.mjs

# trzy osobne terminale/procesy w tle:
node --env-file=.env apps/api/dist/index.js      # terminal 1 - API na :4000
node --env-file=.env apps/worker/dist/index.js   # terminal 2 - worker (pg-boss)
npx -y pnpm@9.12.0 run dev:web                   # terminal 3 - Next.js na :3000
```

Po starcie:

- API: http://localhost:4000/health
- Web: http://localhost:3000/dashboard

**Uwaga:** skrypty `dev:api` i `dev:worker` w `package.json` to obecnie
wyłącznie `tsc --watch` (sam type-check, nie uruchamiają serwera) — dlatego
powyżej używamy zbudowanego `dist/index.js` bezpośrednio, z natywną flagą
Node `--env-file` (wymaga Node ≥ 20.6). Jeśli zmieniasz kod `api`/`worker`
w trakcie pracy, przebuduj dany pakiet (`npx -y pnpm@9.12.0 --filter @unified-osint/api build`)
i zrestartuj proces.

## Docker Compose (opcjonalnie, na później)

```bash
cp .env.example .env
# uzupelnij .env: wygeneruj sekrety (patrz komentarze w pliku), np.:
#   openssl rand -hex 32      # JWT_ACCESS_SECRET / JWT_REFRESH_SECRET
#   openssl rand -base64 24   # POSTGRES_PASSWORD
docker compose up --build
```

Migracje SQL (`packages/db/migrations`) są stosowane automatycznie przez
jednorazowy serwis `migrate` przed startem `api`/`worker`.

Aby włączyć Snusbase, wpisz `SNUSBASE_API_KEY` w lokalnym `.env` i
uruchom `docker compose up --build` ponownie (lub zrestartuj procesy
lokalne) — status źródła w tabeli `sources` przełączy się z
`not_configured` na `active`. Epieos/IntelX pozostają `not_configured`
do czasu uzyskania dostępu API (patrz wyżej).

## Testy

```bash
npx -y pnpm@9.12.0 run test         # testy jednostkowe (core, adapters)
npx -y pnpm@9.12.0 run migrate:test-db && npx -y pnpm@9.12.0 --filter @unified-osint/db test  # testy RLS
```

Testy RLS (`packages/db/tests/rls.test.ts`) wymagają realnego `DATABASE_URL`
i pomijają się bez niego.

## Bezpieczeństwo i zgodność

- SSRF-safe `safeFetch()` z pinningiem DNS dla wszystkich adapterów.
- Circuit breaker per-adapter + trwały status w tabeli `sources`.
- Audit log (`audit_logs`) dla logowań, wyszukiwań i odsłonięć danych wrażliwych.
- Brak przechowywania kluczy API w repo — tylko w lokalnym, gitignorowanym `.env`.
