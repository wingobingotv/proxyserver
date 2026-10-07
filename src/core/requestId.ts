import { randomUUID } from "node:crypto";

export const REQUEST_ID_HEADER = "x-wingo-request-id";

const VALID = /^[A-Za-z0-9._:-]{8,128}$/;

export function newRequestId(): string {
  return randomUUID();
}

/**
 * Request id for a request. A trusted (authenticated) caller's id is kept so
 * one id follows the whole relay path; public callers always get a fresh one.
 */
export function resolveRequestId(incoming: string | string[] | undefined, trusted: boolean): string {
  const value = Array.isArray(incoming) ? incoming[0] : incoming;
  if (trusted && typeof value === "string" && VALID.test(value)) return value;
  return newRequestId();
}

export function isValidRequestId(value: unknown): value is string {
  return typeof value === "string" && VALID.test(value);
}
