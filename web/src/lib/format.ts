const dateTime = new Intl.DateTimeFormat("en-GB", {
  day: "numeric",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});

export function formatDateTime(seconds: number): string {
  return dateTime.format(new Date(seconds * 1000));
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
  const delta = seconds - nowSeconds;
  // Whole minutes, so a token minted a moment ago for an hour reads "in 1 hour", not "in 60 minutes".
  const rounded = nowSeconds + Math.round(delta / 60) * 60;
  const when = delta > 0 && delta < 45 ? "in less than a minute" : formatRelative(rounded, nowSeconds);
  const at = new Date(seconds * 1000);
  const sameDay = at.toDateString() === new Date(nowSeconds * 1000).toDateString();
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

export function initials(name: string): string {
  const words = name.trim().split(/[\s@._-]+/).filter(Boolean);
  return words
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() ?? "")
    .join("");
}

/** Turns free text such as "My App" into a valid slug like "my-app". */
export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}
