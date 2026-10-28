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
- [packages/adapters](packages/adapters) — adaptery źródeł (demo, dns, stuby snusbase/intelx/epieos)
- [packages/db](packages/db) — migracje SQL + runner migracji

Własny Postgres 16 (bez Supabase). Autoryzacja: e-mail + hasło (argon2id),
JWT dostępowy/odświeżający w httpOnly cookies. Row-Level Security wymuszana
przez zmienne sesji Postgresa (`SET LOCAL app.user_id` / `app.role`),
ustawiane wyłącznie przez `withAppContext()` — nigdy ręcznie w zapytaniach.

### Co jest naprawdę zaimplementowane, a co nie

- Działające adaptery: `demo` (dane testowe, oznaczone w UI), `dns`.
- Adaptery w stanie `not_configured` (brak klucza API w `.env`): `snusbase`,
  `intelx`, `epieos`. Zwracają jawny status, nie fałszywe wyniki.
- **Brak** wyszukiwania po haśle (plaintext/wildcard) w bazach wycieków —
  świadomie poza zakresem (ryzyko nadużycia). Adaptery breach-data
  (Snusbase, HIBP) są ograniczone do sprawdzenia, czy dany `email`/`username`
  wystąpił w wycieku i gdzie.

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

Aby włączyć płatne adaptery (Snusbase/Epieos/IntelX), wpisz klucze API w
lokalnym `.env` i uruchom `docker compose up --build` ponownie (lub
zrestartuj procesy lokalne) — status źródła w tabeli `sources` przełączy
się z `not_configured` na `active`.

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
