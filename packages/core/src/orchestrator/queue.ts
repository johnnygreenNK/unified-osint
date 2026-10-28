import PgBoss from "pg-boss";

export const SEARCH_TASK_QUEUE = "search-task";

export interface SearchTaskJobData {
  taskId: string;
  searchId: string;
  sourceId: string;
  userId: string;
  userRole: "admin" | "analyst" | "viewer";
  queryRaw: string;
  queryType: string;
  hasWildcards: boolean;
  correlationId: string;
}

let bossSingleton: PgBoss | undefined;

/**
 * Tworzy (lub zwraca juz utworzona) instancje pg-boss na tym samym Postgresie
 * co dane aplikacji, w dedykowanym schemacie (domyslnie `pgboss`).
 * Jedna instancja Postgresa = jedna mniej usluga do utrzymania w MVP.
 */
export async function getBoss(databaseUrl: string, schema = "pgboss"): Promise<PgBoss> {
  if (bossSingleton) return bossSingleton;
  const boss = new PgBoss({
    connectionString: databaseUrl,
    schema,
    retryLimit: 3,
    retryDelay: 2,
    retryBackoff: true,
    archiveCompletedAfterSeconds: 60 * 60 * 24, // archiwizuj po 24h (zamiast usuwac natychmiast)
    deleteAfterDays: 7,
  });
  boss.on("error", (err) => {
    // eslint-disable-next-line no-console
    console.error("[pg-boss] error", err);
  });
  await boss.start();
  // W pg-boss v10 kolejki sa jawnymi obiektami - send()/work() na kolejce,
  // ktora nie zostala utworzona, nie rzuca bledu, tylko cicho nic nie robi
  // (insert do joba trafia w WHERE po nieistniejacej kolejce). createQueue
  // jest idempotentne (ON CONFLICT DO NOTHING), wiec wywolujemy je zawsze.
  await boss.createQueue(SEARCH_TASK_QUEUE);
  bossSingleton = boss;
  return boss;
}

export async function stopBoss(): Promise<void> {
  if (bossSingleton) {
    await bossSingleton.stop({ graceful: true, timeout: 10_000 });
    bossSingleton = undefined;
  }
}

/**
 * Wysyla zadanie dla jednego (search_id, source_id) z kluczem singleton,
 * ktory gwarantuje, ze pg-boss nie uruchomi dwoch instancji tego samego
 * zadania jednoczesnie (idempotencja na poziomie kolejki, oprocz unikalnego
 * indeksu search_tasks(search_id, source_id) w bazie).
 */
export async function enqueueSearchTask(
  boss: PgBoss,
  data: SearchTaskJobData,
  startAfterSeconds = 0
): Promise<void> {
  await boss.send(SEARCH_TASK_QUEUE, data, {
    singletonKey: `${data.searchId}:${data.sourceId}`,
    retryLimit: 0, // retry per-adapter jest obslugiwany RECZNIE w taskRunner (potrzebujemy klasyfikacji bledu)
    expireInSeconds: 300,
    startAfter: startAfterSeconds,
  });
}
