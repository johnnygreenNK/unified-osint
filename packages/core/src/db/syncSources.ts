import type { Pool } from "pg";
import type { AdapterRegistry } from "../contracts/registry.js";
import { withAppContext, serviceContext } from "./pool.js";

/**
 * Synchronizuje tabele `sources`/`source_capabilities` z rejestrem adapterow
 * w kodzie. Wywolywane przy starcie apps/api i apps/worker, zanim zaczna
 * przyjmowac zadania - `search_tasks.source_id` ma FK do `sources.id`, wiec
 * kazdy adapter w rejestrze musi miec odpowiadajacy wiersz w bazie.
 *
 * Status wyliczany z `isConfigured()`, z jednym wyjatkiem: recznie ustawiony
 * `disabled` (np. przez admina w UI) nie jest nadpisywany przy kazdym starcie.
 */
export async function syncSourcesFromRegistry(pool: Pool, registry: AdapterRegistry): Promise<void> {
  await withAppContext(pool, serviceContext(), async (client) => {
    for (const adapter of registry.list()) {
      const d = adapter.descriptor;
      const status = adapter.isConfigured() ? "active" : "not_configured";

      await client.query(
        `insert into sources (id, name, category, status, adapter_version, required_env_vars, cost_info, updated_at)
         values ($1, $2, $3, $4, $5, $6, $7, now())
         on conflict (id) do update set
           name = excluded.name,
           category = excluded.category,
           status = case when sources.status = 'disabled' then 'disabled' else excluded.status end,
           adapter_version = excluded.adapter_version,
           required_env_vars = excluded.required_env_vars,
           cost_info = excluded.cost_info,
           updated_at = now()`,
        [d.id, d.name, d.category, status, d.adapterVersion, d.requiredEnvVars, JSON.stringify(d.cost)]
      );

      for (const cap of d.capabilities) {
        await client.query(
          `insert into source_capabilities (source_id, query_type, supports_wildcards, max_results)
           values ($1, $2, $3, $4)
           on conflict (source_id, query_type) do update set
             supports_wildcards = excluded.supports_wildcards,
             max_results = excluded.max_results`,
          [d.id, cap.queryType, cap.supportsWildcards, cap.maxResults]
        );
      }
    }
  });
}
