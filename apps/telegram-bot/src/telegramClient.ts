/**
 * Cienki klient oficjalnego Telegram Bot API (core.telegram.org/bots/api,
 * stabilne, publiczne REST API - zweryfikowane, nie zgadywane).
 * Dziala przez long-polling (getUpdates) - bez webhooka/domeny publicznej,
 * co pasuje do lokalnego uruchomienia na Windows.
 */

export interface TelegramUser {
  id: number;
  is_bot: boolean;
  first_name: string;
  username?: string;
}

export interface TelegramMessage {
  message_id: number;
  from?: TelegramUser;
  chat: { id: number; type: string };
  date: number;
  text?: string;
}

export interface TelegramCallbackQuery {
  id: string;
  from: TelegramUser;
  message?: TelegramMessage;
  data?: string;
}

export interface TelegramUpdate {
  update_id: number;
  message?: TelegramMessage;
  callback_query?: TelegramCallbackQuery;
}

export interface InlineKeyboardButton {
  text: string;
  callback_data?: string;
  url?: string;
}

export class TelegramClient {
  private readonly base: string;

  constructor(token: string) {
    this.base = `https://api.telegram.org/bot${token}`;
  }

  private async call<T>(method: string, body: Record<string, unknown>): Promise<T> {
    const res = await fetch(`${this.base}/${method}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const json = (await res.json()) as { ok: boolean; result?: T; description?: string };
    if (!json.ok) {
      throw new Error(`Telegram API ${method} failed: ${json.description ?? res.status}`);
    }
    return json.result as T;
  }

  /** Long-polling o maksymalnie `timeoutSec` sekund (serwer Telegrama trzyma polaczenie otwarte do nowego update'u). */
  async getUpdates(offset: number, timeoutSec = 25): Promise<TelegramUpdate[]> {
    return this.call<TelegramUpdate[]>("getUpdates", {
      offset,
      timeout: timeoutSec,
      allowed_updates: ["message", "callback_query"],
    });
  }

  async sendMessage(
    chatId: number,
    text: string,
    opts?: { replyMarkup?: { inline_keyboard: InlineKeyboardButton[][] }; parseMode?: "HTML" }
  ): Promise<TelegramMessage> {
    return this.call<TelegramMessage>("sendMessage", {
      chat_id: chatId,
      text,
      parse_mode: opts?.parseMode ?? "HTML",
      disable_web_page_preview: true,
      reply_markup: opts?.replyMarkup,
    });
  }

  async editMessageText(
    chatId: number,
    messageId: number,
    text: string,
    opts?: { replyMarkup?: { inline_keyboard: InlineKeyboardButton[][] }; parseMode?: "HTML" }
  ): Promise<void> {
    try {
      await this.call("editMessageText", {
        chat_id: chatId,
        message_id: messageId,
        text,
        parse_mode: opts?.parseMode ?? "HTML",
        disable_web_page_preview: true,
        reply_markup: opts?.replyMarkup,
      });
    } catch (err) {
      // Telegram zwraca blad, gdy nowa tresc jest identyczna z poprzednia -
      // nieszkodliwe przy czestym odswiezaniu statusu wyszukiwania.
      if (!(err instanceof Error) || !err.message.includes("message is not modified")) throw err;
    }
  }

  async answerCallbackQuery(callbackQueryId: string, text?: string): Promise<void> {
    await this.call("answerCallbackQuery", { callback_query_id: callbackQueryId, text });
  }
}

/** Ucieka znaki specjalne HTML dla parse_mode=HTML (Telegram wspiera podzbior tagow). */
export function escapeHtml(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
