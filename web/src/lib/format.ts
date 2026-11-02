const dateTime = new Intl.DateTimeFormat("en-GB", {
  day: "numeric",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});

/** Shown instead of a date the browser cannot represent, such as an expiry millions of years away. */
export const UNKNOWN_DATE = "Unknown date";

/** The date for a Unix time, or null when it is outside what `Date` can hold. */
function dateOf(seconds: number): Date | null {
  if (!Number.isFinite(seconds)) return null;
  const date = new Date(seconds * 1000);
  return Number.isFinite(date.getTime()) ? date : null;
}

export function formatDateTime(seconds: number): string {
  const date = dateOf(seconds);
  return date ? dateTime.format(date) : UNKNOWN_DATE;
}

const relative = new Intl.RelativeTimeFormat("en-GB", { numeric: "auto" });

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["week", 7 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
];

export function formatRelative(seconds: number, nowSeconds = Date.now() / 1000): string {
  if (!dateOf(seconds) || !dateOf(nowSeconds)) return UNKNOWN_DATE;
  const delta = seconds - nowSeconds;
  const abs = Math.abs(delta);
  if (abs < 45) return "just now";
  for (const [unit, size] of UNITS) {
    if (abs >= size) return relative.format(Math.round(delta / size), unit);
  }
  return relative.format(Math.round(delta / 60), "minute");
}

const clock = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit" });

/**
 * When something ends, relative first and the clock time after, such as "in 9 minutes (03:27)".
 * The date is added when it is not today.
 */
export function formatExpiry(seconds: number, nowSeconds = Date.now() / 1000): string {
  const at = dateOf(seconds);
  const now = dateOf(nowSeconds);
  if (!at || !now) return UNKNOWN_DATE;
  const delta = seconds - nowSeconds;
  // Whole minutes, so a token minted a moment ago for an hour reads "in 1 hour", not "in 60 minutes".
  const rounded = nowSeconds + Math.round(delta / 60) * 60;
  const when = delta > 0 && delta < 45 ? "in less than a minute" : formatRelative(rounded, nowSeconds);
  const sameDay = at.toDateString() === now.toDateString();
  return `${when} (${sameDay ? clock.format(at) : formatDateTime(seconds)})`;
}

const WORD_UNITS: [string, number][] = [
  ["day", 86400],
  ["hour", 3600],
  ["minute", 60],
  ["second", 1],
];

/** Durations in words, such as "1 hour", "15 minutes" or "1 day 6 hours". */
export function formatDurationWords(seconds: number): string {
  if (seconds <= 0) return "0 seconds";
  const parts: string[] = [];
  let left = Math.floor(seconds);
  for (const [unit, size] of WORD_UNITS) {
    const count = Math.floor(left / size);
    left -= count * size;
    if (count > 0) parts.push(`${count} ${unit}${count === 1 ? "" : "s"}`);
  }
  return parts.slice(0, 2).join(" ");
}

/** Short human durations such as "1h", "15m" or "1d 6h". */
export function formatDuration(seconds: number): string {
  if (seconds <= 0) return "0s";
  const parts: string[] = [];
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  if (days) parts.push(`${days}d`);
  if (hours) parts.push(`${hours}h`);
  if (minutes) parts.push(`${minutes}m`);
  if (secs && parts.length === 0) parts.push(`${secs}s`);
  return parts.slice(0, 2).join(" ");
}

const DURATION_UNITS: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400, w: 604800, y: 365 * 86400 };
const DURATION_PART = /(\d+)\s*([smhdwy])/gi;

/**
 * Seconds from text such as "3600", "30m", "1h", "90d" or "1h 30m", or null when it is not a
 * duration. A bare number is seconds.
 */
export function parseDuration(text: string): number | null {
  const trimmed = text.trim().toLowerCase();
  if (/^\d+$/.test(trimmed)) {
    const n = Number(trimmed);
    return Number.isSafeInteger(n) ? n : null;
  }
  if (!/^(\d+\s*[smhdwy]\s*)+$/.test(trimmed)) return null;
  let total = 0;
  for (const [, count, unit] of trimmed.matchAll(DURATION_PART)) {
    total += Number(count) * DURATION_UNITS[unit];
  }
  return Number.isSafeInteger(total) ? total : null;
}

/** The shortest exact form of a duration for an input field: 86400 is "1d", 5400 is "90m". */
export function durationText(seconds: number): string {
  for (const [unit, size] of [["d", 86400], ["h", 3600], ["m", 60]] as const) {
    if (seconds > 0 && seconds % size === 0) return `${seconds / size}${unit}`;
  }
  return String(seconds);
}

/** "186 bytes", "12.4 KB" or "1.2 MB". */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return bytes === 1 ? "1 byte" : `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function initials(name: string): string {
  const words = name.trim().split(/[\s@._-]+/).filter(Boolean);
  return words
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() ?? "")
    .join("");
}

/** "org admin" as "Org admin", matching names shown with a capitalised first letter. */
export function upperFirst(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** Turns free text such as "My App" into a valid slug like "my-app". */
export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}
