import type { Charset, Generator } from "../types";

const ALPHABETS: Record<Charset, string> = {
  alphanumeric: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
  symbols: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#%+,-.:=@^_~",
  hex: "0123456789abcdef",
  base64url: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
  numeric: "0123456789",
};

export function alphabet(charset: Charset): string {
  return ALPHABETS[charset];
}

/** A uniformly random value like the server's: bytes that would bias the alphabet are drawn again. */
export function generateValue(generator: Generator): string {
  const chars = ALPHABETS[generator.charset ?? "alphanumeric"];
  const limit = 256 - (256 % chars.length);
  let out = "";
  while (out.length < generator.length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(64))) {
      if (out.length === generator.length) break;
      if (byte < limit) out += chars[byte % chars.length];
    }
  }
  return out;
}
