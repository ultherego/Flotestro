// The panel API client.
//
// Authentication rests on the session cookie set by the control plane. The
// cookie is HttpOnly, so the browser attaches it itself, but state-changing
// requests must send back the CSRF token from the second cookie.

const CSRF_COOKIE = "flotestro_csrf";
const CSRF_HEADER = "X-Flotestro-CSRF";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }

  /** Missing authentication requires a redirect to the login. */
  get unauthenticated() {
    return this.status === 401;
  }

  get forbidden() {
    return this.status === 403;
  }
}

/** The key under which the login screen keeps a bootstrap token for this tab. */
export const BEARER_TOKEN_KEY = "flotestro.token";

// A bootstrap token pasted on the login screen lives in this tab alone;
// the server takes it only when no session cookie came along.
function bearerToken(): string {
  try {
    return sessionStorage.getItem(BEARER_TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

function csrfToken(): string {
  const match = document.cookie
    .split("; ")
    .find((entry) => entry.startsWith(`${CSRF_COOKIE}=`));
  return match ? match.slice(CSRF_COOKIE.length + 1) : "";
}

/**
 * What a caller may add to one request. Headers are for the conditional
 * write: a record read with its entity tag goes back with `If-Match`, so a
 * capacity or a secret written over somebody else's change is refused
 * rather than winning quietly.
 */
export type RequestOptions = { headers?: Record<string, string> };

/** An answer with the part of the response the body does not carry. */
export type WithMeta<T> = {
  data: T;
  /** The entity tag of the record, empty when the server sent none. */
  etag: string;
};

async function requestWithMeta<T>(
  method: string,
  path: string,
  body?: unknown,
  options: RequestOptions = {},
): Promise<WithMeta<T>> {
  const headers: Record<string, string> = { ...options.headers };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") {
    const token = csrfToken();
    if (token) headers[CSRF_HEADER] = token;
  }
  const bearer = bearerToken();
  if (bearer) headers["Authorization"] = `Bearer ${bearer}`;

  const response = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const etag = response.headers.get("ETag") ?? "";

  if (response.status === 204) return { data: undefined as T, etag };

  const text = await response.text();
  let payload: { code?: string; detail?: string } | null = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    // A body that is not JSON is a proxy's page, not the API's answer;
    // the status still says what happened.
  }

  if (!response.ok) {
    throw new ApiError(
      response.status,
      payload?.code ?? "unknown",
      payload?.detail ?? response.statusText,
    );
  }
  return { data: payload as T, etag };
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  options?: RequestOptions,
): Promise<T> {
  return (await requestWithMeta<T>(method, path, body, options)).data;
}

export const api = {
  get: <T>(path: string, options?: RequestOptions) => request<T>("GET", path, undefined, options),
  // A read that needs the entity tag with the record: the tag names the
  // version an editor writes back on.
  getWithMeta: <T>(path: string, options?: RequestOptions) => requestWithMeta<T>("GET", path, undefined, options),
  post: <T>(path: string, body?: unknown, options?: RequestOptions) => request<T>("POST", path, body, options),
  // A whole-list replacement: tags of a host, members of a group.
  put: <T>(path: string, body?: unknown, options?: RequestOptions) => request<T>("PUT", path, body, options),
  // A removal keyed by more than the path - a role binding by its scope -
  // carries the key in the body.
  del: <T>(path: string, body?: unknown, options?: RequestOptions) => request<T>("DELETE", path, body, options),
};

export type Collection<T> = { items: T[]; count: number };

/**
 * One page of a list read by cursor. The server hands back the key of the
 * last row as `next_cursor`; the screen asks for the next page with it and
 * stops when it is empty. `total` comes only from the lists that count.
 */
export type Page<T> = Collection<T> & { next_cursor?: string; total?: number };

/** The rows loaded so far by an infinite query, in one list. */
export function loadedItems<T>(data?: { pages: Page<T>[] }): T[] {
  return data?.pages.flatMap((page) => page.items) ?? [];
}

/** How many rows one request fetches; a screen grows page by page. */
export const LIST_PAGE = 100;
