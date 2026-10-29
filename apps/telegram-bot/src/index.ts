/**
 * Bot Telegram dla UnifiedOSINT - tryb jednoosobowy (TELEGRAM_ALLOWED_USER_ID).
 * Long-polling (bez webhooka/domeny publicznej), tekst wiadomosci = zapytanie
 * wyszukiwania (typ wykrywany automatycznie przez API - detectQueryType()).
 */
import { loadEnv } from "@unified-osint/core";
import { TelegramClient, type InlineKeyboardButton } from "./telegramClient.js";
import { ApiClient, type SseEvent } from "./apiClient.js";
import { formatResultLine, formatSummary, type CanonicalResult } from "./format.js";

const env = loadEnv();

if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_ALLOWED_USER_ID) {
  console.log("[telegram-bot] TELEGRAM_BOT_TOKEN lub TELEGRAM_ALLOWED_USER_ID nie ustawione - bot wylaczony.");
  process.exit(0);
}

const allowedUserId = Number(env.TELEGRAM_ALLOWED_USER_ID);
const tg = new TelegramClient(env.TELEGRAM_BOT_TOKEN);
const api = new ApiClient(env.TELEGRAM_API_BASE_URL);

/** Rekordy ostatniego wyszukiwania per czat - potrzebne do callback_query "Szczegóły". */
const lastResultsByChat = new Map<number, Map<string, CanonicalResult>>();

let shuttingDown = false;
process.on("SIGINT", () => { shuttingDown = true; });
process.on("SIGTERM", () => { shuttingDown = true; });

async function handleSearch(chatId: number, query: string): Promise<void> {
  const trimmed = query.trim();
  if (!trimmed) return;

  let started;
  try {
    started = await api.startSearch(trimmed);
  } catch (err) {
    await tg.sendMessage(chatId, `❌ Nie udało się uruchomić wyszukiwania: ${err instanceof Error ? err.message : String(err)}`);
    return;
  }

  const statusMsg = await tg.sendMessage(chatId, `🔄 Szukam: <code>${trimmed}</code>...`);
  const resultsById = new Map<string, CanonicalResult>();
  let taskCount = 0;
  let doneCount = 0;

  const onEvent = (ev: SseEvent) => {
    if (ev.type === "task.status" || ev.type === "task.error") {
      const status = ev.payload.status as string | undefined;
      if (ev.type === "task.status" && status === "running") taskCount += 1;
      if (status === "succeeded" || status === "failed" || ev.type === "task.error") doneCount += 1;
      tg.editMessageText(
        chatId,
        statusMsg.message_id,
        `🔄 Szukam: <code>${trimmed}</code>...\n📡 Źródła: ${doneCount}/${Math.max(taskCount, doneCount)}`
      ).catch(() => {});
    } else if (ev.type === "result.added" || ev.type === "result.merged") {
      const p = ev.payload;
      const id = p.canonicalRecordId as string;
      resultsById.set(id, {
        canonicalRecordId: id,
        sourceId: p.sourceId as string,
        kind: p.kind as string,
        title: p.title as string,
        sourceCount: p.sourceCount as number,
        attrs: (p.attrs as Record<string, unknown>) ?? {},
      });
    }
  };

  try {
    await api.streamSearchEvents(started.searchId, onEvent, { timeoutMs: 60_000 });
  } catch (err) {
    await tg.sendMessage(chatId, `❌ Błąd podczas pobierania wyników: ${err instanceof Error ? err.message : String(err)}`);
    return;
  }

  lastResultsByChat.set(chatId, resultsById);
  const results = [...resultsById.values()];

  if (results.length === 0) {
    await tg.editMessageText(chatId, statusMsg.message_id, `📭 Brak wyników dla: <code>${trimmed}</code>`);
    return;
  }

  await tg.editMessageText(chatId, statusMsg.message_id, formatSummary(results, false, 0));

  for (const r of results) {
    const keyboard: InlineKeyboardButton[][] = [[{ text: "🔎 Szczegóły", callback_data: `detail:${r.canonicalRecordId}` }]];
    await tg.sendMessage(chatId, formatResultLine(r), { replyMarkup: { inline_keyboard: keyboard } });
  }
}

async function handleDetailCallback(chatId: number, canonicalRecordId: string): Promise<void> {
  try {
    const detail = await api.fetchCanonicalRecord(canonicalRecordId);
    const lines = [`<b>${detail.title}</b>`, `Typ: ${detail.kind}`, `Źródeł: ${detail.source_count}`, ""];
    for (const [k, v] of Object.entries(detail.attrs)) {
      if (v === null || v === undefined || v === "") continue;
      lines.push(`<b>${k}:</b> <code>${String(v)}</code>`);
    }
    await tg.sendMessage(chatId, lines.join("\n"));
  } catch (err) {
    await tg.sendMessage(chatId, `❌ Nie udało się pobrać szczegółów: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function pollLoop(): Promise<void> {
  let offset = 0;
  while (!shuttingDown) {
    let updates;
    try {
      updates = await tg.getUpdates(offset);
    } catch (err) {
      console.error("[telegram-bot] getUpdates failed:", err);
      await new Promise((r) => setTimeout(r, 3000));
      continue;
    }

    for (const update of updates) {
      offset = update.update_id + 1;

      const incomingText = update.message?.text;
      if (update.message && incomingText) {
        const msg = update.message;
        const userId = msg.from?.id;
        const chatId = msg.chat.id;
        if (userId !== allowedUserId) {
          await tg.sendMessage(chatId, "⛔ Brak dostępu.").catch(() => {});
          continue;
        }
        const text = incomingText.trim();
        if (text === "/start") {
          await tg.sendMessage(chatId, "👋 UnifiedOSINT bot.\nWyślij zapytanie (email, username, domena, IP...) aby wyszukać.");
        } else {
          handleSearch(chatId, text).catch((err) => console.error("[telegram-bot] handleSearch error:", err));
        }
      } else if (update.callback_query) {
        const cb = update.callback_query;
        const userId = cb.from.id;
        const chatId = cb.message?.chat.id;
        await tg.answerCallbackQuery(cb.id).catch(() => {});
        if (userId !== allowedUserId || !chatId) continue;
        if (cb.data?.startsWith("detail:")) {
          const id = cb.data.slice("detail:".length);
          handleDetailCallback(chatId, id).catch((err) => console.error("[telegram-bot] handleDetailCallback error:", err));
        }
      }
    }
  }
}

async function main(): Promise<void> {
  console.log(`[telegram-bot] logowanie do API: ${env.TELEGRAM_API_BASE_URL}`);
  await api.autoLogin();
  console.log(`[telegram-bot] zalogowano, start long-polling (user_id=${allowedUserId})`);
  await pollLoop();
  console.log("[telegram-bot] zatrzymano.");
}

main().catch((err) => {
  console.error("[telegram-bot] fatal:", err);
  process.exit(1);
});
