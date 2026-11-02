export const MAX_LOGO_BYTES = 512 * 1024;
export const MAX_LOGO_DIMENSION = 4096;

export type ImageType = "image/png" | "image/jpeg" | "image/gif" | "image/webp" | "image/svg+xml";

export interface SniffedImage {
  type: ImageType;
  /** Pixel size read from the header; absent for SVG or when the header is cut short. */
  width?: number;
  height?: number;
}

const PNG_MAGIC = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

function startsWith(bytes: Uint8Array, prefix: readonly number[], at = 0): boolean {
  return prefix.every((b, i) => bytes[at + i] === b);
}

function ascii(text: string): number[] {
  return Array.from(text, (c) => c.charCodeAt(0));
}

function u16be(bytes: Uint8Array, at: number): number {
  return (bytes[at] << 8) | bytes[at + 1];
}

function u32be(bytes: Uint8Array, at: number): number {
  return ((bytes[at] << 24) | (bytes[at + 1] << 16) | (bytes[at + 2] << 8) | bytes[at + 3]) >>> 0;
}

function u16le(bytes: Uint8Array, at: number): number {
  return bytes[at] | (bytes[at + 1] << 8);
}

function u24le(bytes: Uint8Array, at: number): number {
  return bytes[at] | (bytes[at + 1] << 8) | (bytes[at + 2] << 16);
}

function sized(type: ImageType, bytes: Uint8Array, need: number, read: () => [number, number]): SniffedImage {
  if (bytes.length < need) return { type };
  const [width, height] = read();
  return { type, width, height };
}

function jpegSize(bytes: Uint8Array): SniffedImage {
  let at = 2;
  while (at + 9 < bytes.length) {
    if (bytes[at] !== 0xff) return { type: "image/jpeg" };
    const marker = bytes[at + 1];
    const isFrame = marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker);
    if (isFrame) return { type: "image/jpeg", height: u16be(bytes, at + 5), width: u16be(bytes, at + 7) };
    at += 2 + u16be(bytes, at + 2);
  }
  return { type: "image/jpeg" };
}

function webpSize(bytes: Uint8Array): SniffedImage {
  const type = "image/webp";
  if (startsWith(bytes, ascii("VP8 "), 12)) {
    return sized(type, bytes, 30, () => [u16le(bytes, 26) & 0x3fff, u16le(bytes, 28) & 0x3fff]);
  }
  if (startsWith(bytes, ascii("VP8L"), 12)) {
    return sized(type, bytes, 25, () => [
      1 + (((bytes[22] & 0x3f) << 8) | bytes[21]),
      1 + (((bytes[24] & 0x0f) << 10) | (bytes[23] << 2) | ((bytes[22] & 0xc0) >> 6)),
    ]);
  }
  if (startsWith(bytes, ascii("VP8X"), 12)) {
    return sized(type, bytes, 30, () => [1 + u24le(bytes, 24), 1 + u24le(bytes, 27)]);
  }
  return { type };
}

function decodeText(bytes: Uint8Array): string | undefined {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}

function looksLikeSvg(bytes: Uint8Array): boolean {
  const text = decodeText(bytes);
  if (text === undefined) return false;
  // trimStart also drops a leading byte order mark.
  const start = text.trimStart();
  return start.startsWith("<") && start.includes("<svg");
}

/** Identifies an image by its magic bytes, the way the server does, and reads its size when it can. */
export function sniffImage(bytes: Uint8Array): SniffedImage | undefined {
  if (startsWith(bytes, PNG_MAGIC)) return sized("image/png", bytes, 24, () => [u32be(bytes, 16), u32be(bytes, 20)]);
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return jpegSize(bytes);
  if (startsWith(bytes, ascii("GIF87a")) || startsWith(bytes, ascii("GIF89a"))) {
    return sized("image/gif", bytes, 10, () => [u16le(bytes, 6), u16le(bytes, 8)]);
  }
  if (bytes.length >= 12 && startsWith(bytes, ascii("RIFF")) && startsWith(bytes, ascii("WEBP"), 8)) {
    return webpSize(bytes);
  }
  if (looksLikeSvg(bytes)) return { type: "image/svg+xml" };
  return undefined;
}

export type LogoCheck = { ok: true; type: ImageType } | { ok: false; message: string };

/** Quick checks before uploading, so obvious mistakes do not need a round trip. */
export function checkLogoFile(bytes: Uint8Array): LogoCheck {
  if (bytes.length > MAX_LOGO_BYTES) return { ok: false, message: "Logos can be at most 512 KiB." };
  const image = sniffImage(bytes);
  if (!image) return { ok: false, message: "Choose a PNG, JPEG, GIF, WebP or SVG image." };
  const { width = 0, height = 0 } = image;
  if (width > MAX_LOGO_DIMENSION || height > MAX_LOGO_DIMENSION) {
    return { ok: false, message: `The image is larger than ${MAX_LOGO_DIMENSION} by ${MAX_LOGO_DIMENSION} pixels.` };
  }
  return { ok: true, type: image.type };
}

/** What stops an SVG being drawn into a PNG in the browser, if anything. */
export function svgProblem(bytes: Uint8Array): string | undefined {
  const text = decodeText(bytes) ?? "";
  // Entity definitions can expand without limit, so a document type is refused outright.
  if (/<!DOCTYPE/i.test(text)) return "SVGs with a document type cannot be used. Save the logo as a PNG instead.";
  const root = text.match(/<svg\b[^>]*>/i)?.[0] ?? "";
  if (!/xmlns\s*=\s*["']http:\/\/www\.w3\.org\/2000\/svg["']/.test(root)) {
    return "That SVG has no SVG namespace, so browsers cannot draw it. Save the logo as a PNG instead.";
  }
  return undefined;
}

export type ImageValidation = { ok: true; type: ImageType } | { ok: false; message: string };

/**
 * The server decodes raster images fully; this approximates that with header checks so the mock
 * refuses the same kinds of file with the same messages. Like the server, it refuses SVG.
 */
export function validateImage(bytes: Uint8Array): ImageValidation {
  const image = sniffImage(bytes);
  if (!image) return { ok: false, message: "the file is not a PNG, JPEG, GIF or WebP image" };
  if (image.type === "image/svg+xml") {
    return { ok: false, message: "SVG files are not accepted; convert the logo to PNG first" };
  }
  const { width, height } = image;
  if (width === undefined || height === undefined) {
    return { ok: false, message: "the image could not be read: the header is incomplete" };
  }
  if (width === 0 || height === 0) return { ok: false, message: "the image could not be read: the image is empty" };
  if (width > MAX_LOGO_DIMENSION || height > MAX_LOGO_DIMENSION) {
    return { ok: false, message: `the image is larger than ${MAX_LOGO_DIMENSION} by ${MAX_LOGO_DIMENSION} pixels` };
  }
  const truncatedPng = image.type === "image/png" && !containsSequence(bytes, ascii("IEND"));
  if (truncatedPng) return { ok: false, message: "the image could not be read: unexpected end of file" };
  return { ok: true, type: image.type };
}

function containsSequence(bytes: Uint8Array, needle: readonly number[]): boolean {
  for (let i = bytes.length - needle.length; i >= 0; i -= 1) {
    if (startsWith(bytes, needle, i)) return true;
  }
  return false;
}
