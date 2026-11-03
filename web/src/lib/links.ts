export const DOCS_URL = "https://sam-ruff.github.io/sekret/";

/** Router state that opens a secret's drawer on arrival, kept out of the address bar. */
export interface OpenSecretState {
  open: string;
  /** Start the drawer at its access section. */
  access?: boolean;
}

export function openSecretState(state: unknown): OpenSecretState | null {
  if (typeof state !== "object" || state === null) return null;
  const { open, access } = state as Record<string, unknown>;
  if (typeof open !== "string") return null;
  return { open, access: access === true };
}
