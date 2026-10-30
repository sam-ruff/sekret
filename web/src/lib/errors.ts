import { ApiError } from "@/api/client";

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return capitalise(error.message);
  if (error instanceof Error && error.message) return error.message;
  return "Something went wrong.";
}

export function isEscalation(error: unknown): error is ApiError {
  return error instanceof ApiError && error.status === 403 && error.code === "escalation";
}

export function isNotFound(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404;
}

function capitalise(text: string): string {
  return text ? text[0].toUpperCase() + text.slice(1) : text;
}
