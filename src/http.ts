/** Response helpers and the headers that harden every API reply. */

const SECURITY_HEADERS: Record<string, string> = {
  "content-type": "application/json; charset=utf-8",
  // API responses are secrets in transit and must never touch a cache.
  "cache-control": "no-store, no-cache, must-revalidate, private",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
};

export function json(body: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
  return new Response(JSON.stringify(body), { ...init, headers });
}

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message?: string,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message ?? code);
  }
}

export const badRequest = (msg: string) => new HttpError(400, "bad_request", msg);
export const unauthorized = (msg = "Not signed in.") => new HttpError(401, "unauthorized", msg);
export const notFound = (msg = "Not found.") => new HttpError(404, "not_found", msg);
export const conflict = (msg: string, extra?: Record<string, unknown>) =>
  new HttpError(409, "conflict", msg, extra);

export function errorResponse(err: unknown): Response {
  if (err instanceof HttpError) {
    return json({ error: err.code, message: err.message, ...err.extra }, { status: err.status });
  }
  console.error("unhandled", err);
  return json({ error: "internal", message: "Something went wrong." }, { status: 500 });
}

/** Reads and validates a JSON body, with a hard cap so a huge POST cannot wedge the Worker. */
export async function readJson<T = Record<string, unknown>>(
  request: Request,
  maxBytes = 8 * 1024 * 1024,
): Promise<T> {
  const len = Number(request.headers.get("content-length") ?? "0");
  if (len > maxBytes) throw new HttpError(413, "too_large", "Request body is too large.");
  let parsed: unknown;
  try {
    parsed = await request.json();
  } catch {
    throw badRequest("Body must be valid JSON.");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw badRequest("Body must be a JSON object.");
  }
  return parsed as T;
}

export function requireString(
  body: Record<string, unknown>,
  field: string,
  { max = 4096, min = 1 }: { max?: number; min?: number } = {},
): string {
  const value = body[field];
  if (typeof value !== "string") throw badRequest(`"${field}" is required.`);
  const trimmed = value.trim();
  if (trimmed.length < min) throw badRequest(`"${field}" must not be empty.`);
  if (value.length > max) throw badRequest(`"${field}" is too long.`);
  return trimmed;
}

export function requireInt(
  body: Record<string, unknown>,
  field: string,
  { min, max }: { min: number; max: number },
): number {
  const value = body[field];
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw badRequest(`"${field}" must be an integer.`);
  }
  if (value < min || value > max) {
    throw badRequest(`"${field}" must be between ${min} and ${max}.`);
  }
  return value;
}

export const clientIp = (request: Request): string =>
  request.headers.get("cf-connecting-ip") ?? "unknown";
