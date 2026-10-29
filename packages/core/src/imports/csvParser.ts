/**
 * Parser CSV z auto-detekcja separatora - inspirowany podejsciem
 * githubesson/csves (CSV -> Elasticsearch), ale bez zaleznosci od ES:
 * zwraca proste wiersze klucz-wartosc do dalszej normalizacji.
 */

const CANDIDATE_DELIMITERS = [",", ";", "\t", "|"];

/** Dzieli jedna linie CSV na pola, respektujac cytowanie `"..."` i `""` jako escape. */
function splitCsvLine(line: string, delimiter: string): string[] {
  const fields: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (inQuotes) {
      if (char === '"') {
        if (line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        current += char;
      }
    } else if (char === '"') {
      inQuotes = true;
    } else if (char === delimiter) {
      fields.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  fields.push(current);
  return fields;
}

/** Wybiera separator, ktory daje najwiecej kolumn (>1) w linii naglowka. */
export function detectDelimiter(headerLine: string): string {
  let best = CANDIDATE_DELIMITERS[0]!;
  let bestCount = 0;
  for (const delimiter of CANDIDATE_DELIMITERS) {
    const count = splitCsvLine(headerLine, delimiter).length;
    if (count > bestCount) {
      bestCount = count;
      best = delimiter;
    }
  }
  return best;
}

/** Usuwa biale znaki i znaki kontrolne - jak czyszczenie w csves. */
function cleanField(value: string): string {
  return value.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, "").trim();
}

export interface ParsedCsvResult {
  headers: string[];
  rows: Record<string, string>[];
}

/**
 * Parsuje cala zawartosc CSV. Pierwsza niepusta linia = naglowek.
 * Wiersze z inna liczba pol niz naglowek nie sa odrzucane - brakujace
 * pola zostaja pusta, dodatkowe sa obcinane (dane z realnych wyciekow
 * czesto nie sa idealnie regularne).
 */
export function parseCsv(content: string, delimiter?: string): ParsedCsvResult {
  const lines = content.split(/\r?\n/).filter((l) => l.length > 0);
  if (lines.length === 0) return { headers: [], rows: [] };

  const sep = delimiter ?? detectDelimiter(lines[0]!);
  const headers = splitCsvLine(lines[0]!, sep).map((h) => cleanField(h));

  const rows: Record<string, string>[] = [];
  for (let i = 1; i < lines.length; i++) {
    const fields = splitCsvLine(lines[i]!, sep);
    const row: Record<string, string> = {};
    for (let col = 0; col < headers.length; col++) {
      row[headers[col]!] = cleanField(fields[col] ?? "");
    }
    rows.push(row);
  }
  return { headers, rows };
}
