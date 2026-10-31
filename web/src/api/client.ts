import createClient, { type Middleware } from "openapi-fetch";
import { safeReturnTo } from "@/lib/safe-url";
import type { paths } from "./schema";
import type { PassphraseStrength } from "./types";

export const mockMode = import.meta.env.MODE === "mock";

export const CSRF_HEADER = "x-sekret-csrf";

type FetchLike = (input: Request) => Promise<Response>;

/** In mock mode every request is answered by the in-memory fake, loaded lazily so it stays out of production. */
const transport: FetchLike = mockMode
  ? async (request) => (await import("./mock/server")).mockFetch(request)
  : (request) => globalThis.fetch(request);

/** A failed API call carrying the server's error code and human message. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  /** zxcvbn's feedback when the server refuses a weak passphrase. */
  readonly strength?: PassphraseStrength;

  constructor(message: string, status: number, code: string, strength?: PassphraseStrength) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.strength = strength;
  }

  static from(status: number, body: unknown): ApiError {
    const value = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
    const code = typeof value.error === "string" ? value.error : `http-${status}`;
    const message =
      typeof value.message === "string" && value.message ? value.message : fallbackMessage(status);
    return new ApiError(message, status, code, strengthFrom(value.strength));
  }
}

function strengthFrom(value: unknown): PassphraseStrength | undefined {
  if (!value || typeof value !== "object") return undefined;
  const candidate = value as Partial<PassphraseStrength>;
  if (typeof candidate.score !== "number" || !Array.isArray(candidate.suggestions)) return undefined;
  return {
    score: candidate.score,
    acceptable: candidate.acceptable === true,
    warning: typeof candidate.warning === "string" ? candidate.warning : null,
    suggestions: candidate.suggestions.filter((s): s is string => typeof s === "string"),
  };
}

function fallbackMessage(status: number): string {
  if (status === 0) return "The server could not be reached.";
  if (status === 401) return "Your session has ended. Please sign in again.";
  if (status === 403) return "You do not have permission to do that.";
  if (status === 404) return "Not found.";
  if (status === 429) return "Too many attempts. Wait a minute and try again.";
  return `The request failed (${status}).`;
}

/** The server answers 503 with one of these codes until it is set up and unlocked. */
const SEAL_CODES = new Set(["sealed", "uninitialised"]);

export function isSealError(error: unknown): error is ApiError {
  return error instanceof ApiError && error.status === 503 && SEAL_CODES.has(error.code);
}

type SealListener = () => void;
const sealListeners = new Set<SealListener>();

/** Called whenever a request finds the server sealed or not set up, which can happen while a tab is open. */
export function onSealResponse(listener: SealListener): () => void {
  sealListeners.add(listener);
  return () => {
    sealListeners.delete(listener);
  };
}

export function loginPath(returnTo: string): string {
  return `/login?return_to=${encodeURIComponent(returnTo)}`;
}

function currentLocation(): string {
  return `${window.location.pathname}${window.location.search}`;
}

/** Sends the browser to the login page unless it is already there. */
export function redirectToLogin(): void {
  if (window.location.pathname === "/login") return;
  window.location.assign(loginPath(currentLocation()));
}

const csrf: Middleware = {
  onRequest({ request }) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      request.headers.set(CSRF_HEADER, "1");
    }
    return request;
  },
};

export const client = createClient<paths>({
  baseUrl: "",
  credentials: "same-origin",
  fetch: transport,
});
client.use(csrf);

interface FetchResult<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

/** 401 codes that mean a wrong secret was typed, not that the session ended. */
const WRONG_SECRET_CODES = new Set(["invalid_passphrase", "invalid_setup_code"]);

function failure(response: Response, body: unknown): ApiError {
  const error = ApiError.from(response.status, body);
  if (response.status === 401 && !WRONG_SECRET_CODES.has(error.code)) redirectToLogin();
  if (isSealError(error)) sealListeners.forEach((listener) => listener());
  return error;
}

/** Turns an openapi-fetch result into data or a thrown `ApiError`, handling expired sessions and a sealed server. */
export async function unwrap<T>(pending: Promise<FetchResult<T>>): Promise<T> {
  let result: FetchResult<T>;
  try {
    result = await pending;
  } catch {
    throw ApiError.from(0, undefined);
  }
  if (result.response.ok) return result.data as T;
  throw failure(result.response, result.error);
}

export interface Download {
  blob: Blob;
  filename: string;
}

function filenameFrom(disposition: string | null, fallback: string): string {
  const match = disposition?.match(/filename="?([^";]+)"?/);
  return match?.[1] ?? fallback;
}

/** Fetches an attachment, keeping the filename the server suggests. */
export async function fetchDownload(path: string, fallbackName: string): Promise<Download> {
  let response: Response;
  try {
    response = await transport(new Request(new URL(path, window.location.origin), { credentials: "same-origin" }));
  } catch {
    throw ApiError.from(0, undefined);
  }
  if (!response.ok) {
    const body: unknown = await response.json().catch(() => undefined);
    throw failure(response, body);
  }
  return { blob: await response.blob(), filename: filenameFrom(response.headers.get("Content-Disposition"), fallbackName) };
}

/** Fetches a binary resource such as a logo through the same transport as the API, so mock mode can serve it. */
export async function fetchBlob(url: string): Promise<Blob> {
  const response = await transport(new Request(new URL(url, window.location.origin), { credentials: "same-origin" }));
  if (!response.ok) throw ApiError.from(response.status, undefined);
  return response.blob();
}

/** Full-page navigation to the server's OIDC login; mock mode signs in immediately. */
export function startSignIn(returnTo: string): void {
  const safe = safeReturnTo(returnTo);
  if (mockMode) {
    void import("./mock/server").then((mock) => {
      mock.mockSignIn();
      window.location.assign(safe);
    });
    return;
  }
  window.location.assign(`/auth/login?return_to=${encodeURIComponent(safe)}`);
}
