import createClient, { type Middleware } from "openapi-fetch";
import { safeReturnTo } from "@/lib/safe-url";
import type { paths } from "./schema";

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

  constructor(message: string, status: number, code: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }

  static from(status: number, body: unknown): ApiError {
    const value = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
    const code = typeof value.error === "string" ? value.error : `http-${status}`;
    const message =
      typeof value.message === "string" && value.message ? value.message : fallbackMessage(status);
    return new ApiError(message, status, code);
  }
}

function fallbackMessage(status: number): string {
  if (status === 0) return "The server could not be reached.";
  if (status === 401) return "Your session has ended. Please sign in again.";
  if (status === 403) return "You do not have permission to do that.";
  if (status === 404) return "Not found.";
  return `The request failed (${status}).`;
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

/** Turns an openapi-fetch result into data or a thrown `ApiError`, handling expired sessions. */
export async function unwrap<T>(pending: Promise<FetchResult<T>>): Promise<T> {
  let result: FetchResult<T>;
  try {
    result = await pending;
  } catch {
    throw ApiError.from(0, undefined);
  }
  if (result.response.ok) return result.data as T;
  if (result.response.status === 401) redirectToLogin();
  throw ApiError.from(result.response.status, result.error);
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
