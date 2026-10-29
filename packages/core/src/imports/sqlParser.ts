/**
 * Parser instrukcji `INSERT INTO ... VALUES (...)` ze zrzutow SQL (np.
 * mysqldump) - inspirowany githubesson/sqlparser, przepisany na TS bez
 * zaleznosci od zewnetrznej binarki. Nie jest to pelny parser SQL: obsluguje
 * jedna, najczestsza forme uzywana w zrzutach wyciekow danych, i pomija
 * wszystko inne (CREATE TABLE, komentarze, itp.) bez bledu.
 */

export interface ParsedSqlTable {
  table: string;
  columns: string[];
  rows: Record<string, string | null>[];
}

const INSERT_HEAD = /insert\s+into\s+[`"]?([a-zA-Z0-9_]+)[`"]?\s*\(([^)]*)\)\s*values\s*/gi;

/** Parsuje liste kolumn z `(col1, col2, ...)`, usuwajac cytowanie backtick/dquote. */
function parseColumnList(raw: string): string[] {
  return raw
    .split(",")
    .map((c) => c.trim().replace(/^[`"]|[`"]$/g, ""))
    .filter((c) => c.length > 0);
}

/**
 * Od pozycji `start` (zaraz po "VALUES") czyta kolejne krotki `(...)` az do
 * `;` poza krotka. Respektuje cytowanie '...'/"..." z escape'owaniem `\` i `''`.
 * Zwraca liste surowych pol (string lub null dla SQL NULL) per krotka oraz
 * pozycje, na ktorej skonczyl (za `;`).
 */
function readTuples(sql: string, start: number): { tuples: (string | null)[][]; endIndex: number } {
  const tuples: (string | null)[][] = [];
  let i = start;

  while (i < sql.length) {
    while (i < sql.length && /\s/.test(sql[i]!)) i++;
    if (sql[i] === ";") {
      i++;
      break;
    }
    if (sql[i] === ",") {
      i++;
      continue;
    }
    if (sql[i] !== "(") break;

    i++; // skip '('
    const fields: (string | null)[] = [];
    let current = "";
    let quote: '"' | "'" | null = null;
    let sawUnquoted = false;

    while (i < sql.length) {
      const char = sql[i]!;
      if (quote) {
        if (char === "\\" && i + 1 < sql.length) {
          current += sql[i + 1];
          i += 2;
          continue;
        }
        if (char === quote) {
          if (sql[i + 1] === quote) {
            current += quote;
            i += 2;
            continue;
          }
          quote = null;
          i++;
          continue;
        }
        current += char;
        i++;
        continue;
      }
      if (char === "'" || char === '"') {
        quote = char;
        i++;
        continue;
      }
      if (char === ")") {
        fields.push(sawUnquoted && current.trim().toUpperCase() === "NULL" ? null : current);
        i++;
        break;
      }
      if (char === ",") {
        fields.push(sawUnquoted && current.trim().toUpperCase() === "NULL" ? null : current);
        current = "";
        sawUnquoted = false;
        i++;
        continue;
      }
      current += char;
      sawUnquoted = true;
      i++;
    }
    tuples.push(fields);
  }

  return { tuples, endIndex: i };
}

/** Parsuje caly zrzut SQL, grupujac wiersze per tabela (`-all` jak w sqlparser). */
export function parseSqlDump(content: string): ParsedSqlTable[] {
  const tables = new Map<string, ParsedSqlTable>();
  let match: RegExpExecArray | null;

  INSERT_HEAD.lastIndex = 0;
  while ((match = INSERT_HEAD.exec(content)) !== null) {
    const tableName = match[1]!;
    const columns = parseColumnList(match[2]!);
    const valuesStart = INSERT_HEAD.lastIndex;
    const { tuples, endIndex } = readTuples(content, valuesStart);
    INSERT_HEAD.lastIndex = endIndex;

    let entry = tables.get(tableName);
    if (!entry) {
      entry = { table: tableName, columns, rows: [] };
      tables.set(tableName, entry);
    }

    for (const tuple of tuples) {
      const row: Record<string, string | null> = {};
      for (let col = 0; col < columns.length; col++) {
        row[columns[col]!] = tuple[col] ?? null;
      }
      entry.rows.push(row);
    }
  }

  return [...tables.values()];
}
