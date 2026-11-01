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

export interface ApproveState {
  typed: string;
  mismatch: boolean;
  /** The request's details have loaded. */
  loaded: boolean;
  otherAddress: boolean;
  confirmedOwn: boolean;
}

/** Why Approve is disabled, or undefined when it can be pressed. */
export function approveBlocker(state: ApproveState): string | undefined {
  if (!isCompleteCode(state.typed)) return "Type the code from your terminal to approve.";
  if (state.mismatch) return "The code does not match this request.";
  if (!state.loaded) return "Checking the request…";
  if (state.otherAddress && !state.confirmedOwn) return 'Tick "I started this sign-in myself" to approve.';
  return undefined;
}

/** Whether the code typed matches the one the request is for, however it was spaced or cased. */
export function codesMatch(typed: string, expected: string): boolean {
  return isCompleteCode(typed) && normaliseUserCode(typed) === normaliseUserCode(expected);
}
