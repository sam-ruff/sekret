/** CLI login codes look like `BCDF-2345`: two groups of four. */
const CODE_LENGTH = 8;

/** Uppercases and drops anything but letters and digits, then puts the dash back, as the server does. */
export function normaliseUserCode(code: string): string {
  const plain = code.replace(/[^A-Za-z0-9]/g, "").toUpperCase();
  return plain.length === CODE_LENGTH ? `${plain.slice(0, 4)}-${plain.slice(4)}` : plain;
}

export function isCompleteCode(code: string): boolean {
  return /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(normaliseUserCode(code));
}

/** Whether the code typed matches the one the request is for, however it was spaced or cased. */
export function codesMatch(typed: string, expected: string): boolean {
  return isCompleteCode(typed) && normaliseUserCode(typed) === normaliseUserCode(expected);
}
