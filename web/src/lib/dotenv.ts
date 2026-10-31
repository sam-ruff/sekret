export interface EnvEntry {
  key: string;
  value: string;
}

export interface EnvParseIssue {
  line: number;
  message: string;
}

/** A key set on more than one line; the last line wins. */
export interface EnvDuplicate {
  key: string;
  /** The line whose value is used. */
  line: number;
  /** The earlier lines that set it too. */
  earlier: number[];
}

function lineList(lines: number[]): string {
  if (lines.length === 1) return `line ${lines[0]}`;
  return `lines ${lines.slice(0, -1).join(", ")} and ${lines[lines.length - 1]}`;
}

/** Such as "Line 6: API_URL is also on line 1. The value from line 6 is used." */
export function duplicateText(duplicate: EnvDuplicate): string {
  return `Line ${duplicate.line}: ${duplicate.key} is also on ${lineList(duplicate.earlier)}. The value from line ${duplicate.line} is used.`;
}

export interface EnvParseResult {
  entries: EnvEntry[];
  issues: EnvParseIssue[];
  duplicates: EnvDuplicate[];
}

const KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_.-]*$/;

export function isValidSecretKey(key: string): boolean {
  return key.length <= 256 && KEY_PATTERN.test(key);
}

function unescapeDouble(raw: string): string {
  return raw.replace(/\\([nrt"\\])/g, (_, c: string) => {
    if (c === "n") return "\n";
    if (c === "r") return "\r";
    if (c === "t") return "\t";
    return c;
  });
}

/** Index of the closing quote, skipping backslash escapes inside double quotes. */
function closingQuote(text: string, quote: string, from: number): number {
  for (let i = from; i < text.length; i += 1) {
    if (quote === '"' && text[i] === "\\") {
      i += 1;
      continue;
    }
    if (text[i] === quote) return i;
  }
  return -1;
}

/**
 * Parses `.env` text: `KEY=value` lines, optional `export`, `#` comments, single, double and
 * backtick quoted values (double quoted ones may span lines and use escapes). Later keys win.
 */
export function parseDotenv(text: string): EnvParseResult {
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const found = new Map<string, string>();
  const seenOn = new Map<string, number[]>();
  const issues: EnvParseIssue[] = [];
  const set = (key: string, value: string, line: number) => {
    found.set(key, value);
    seenOn.set(key, [...(seenOn.get(key) ?? []), line]);
  };

  for (let index = 0; index < lines.length; index += 1) {
    const lineNumber = index + 1;
    const trimmed = lines[index].trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;

    const body = trimmed.replace(/^export\s+/, "");
    const eq = body.indexOf("=");
    if (eq <= 0) {
      issues.push({ line: lineNumber, message: "expected KEY=value" });
      continue;
    }
    const key = body.slice(0, eq).trim();
    if (!isValidSecretKey(key)) {
      issues.push({ line: lineNumber, message: `${key} is not a valid key` });
      continue;
    }

    let rest = body.slice(eq + 1).trimStart();
    const quote = rest[0];
    if (quote !== '"' && quote !== "'" && quote !== "`") {
      set(key, rest.replace(/\s+#.*$/, "").trim(), lineNumber);
      continue;
    }

    let end = closingQuote(rest, quote, 1);
    while (end === -1 && quote === '"' && index + 1 < lines.length) {
      index += 1;
      rest += `\n${lines[index]}`;
      end = closingQuote(rest, quote, 1);
    }
    if (end === -1) {
      issues.push({ line: lineNumber, message: `unterminated quote for ${key}` });
      continue;
    }
    const inner = rest.slice(1, end);
    set(key, quote === '"' ? unescapeDouble(inner) : inner, lineNumber);
  }

  const duplicates = Array.from(seenOn)
    .filter(([, lines]) => lines.length > 1)
    .map(([key, lines]) => ({ key, line: lines[lines.length - 1], earlier: lines.slice(0, -1) }))
    .sort((a, b) => a.line - b.line);
  return { entries: Array.from(found, ([key, value]) => ({ key, value })), issues, duplicates };
}
