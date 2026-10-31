// Browsers treat a backslash like a slash, so "/\evil.example" would leave the origin; they also drop tabs and newlines.
function hasUnsafeCharacter(value: string): boolean {
  return Array.from(value).some((c) => c === "\\" || c.charCodeAt(0) < 0x20 || c.charCodeAt(0) === 0x7f);
}

function sameOriginPath(value: string, origin: string): string | undefined {
  if (!value.startsWith("/") || value.startsWith("//") || hasUnsafeCharacter(value)) return undefined;
  try {
    const url = new URL(value, origin);
    if (url.origin !== new URL(origin).origin) return undefined;
    // "/..//x" normalises to "//x", which a browser reads as another host.
    if (url.pathname.startsWith("//") || url.pathname.startsWith("/\\")) return undefined;
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return undefined;
  }
}

/** A same-origin path to return to after signing in, or "/" for anything else. */
export function safeReturnTo(value: string | null | undefined, origin = window.location.origin): string {
  return (value && sameOriginPath(value, origin)) || "/";
}

/** The URL if it is an absolute http(s) link, so `javascript:` and other schemes never reach an href or navigation. */
export function safeHttpUrl(value: string | null | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : undefined;
  } catch {
    return undefined;
  }
}

/** Logos are only ever loaded from the API on this origin. */
export function safeLogoUrl(value: string | null | undefined, origin = window.location.origin): string | undefined {
  if (!value) return undefined;
  const path = sameOriginPath(value, origin);
  return path?.startsWith("/api/v1/") ? path : undefined;
}
