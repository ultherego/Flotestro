// Klient API panelu.
//
// Uwierzytelnienie opiera sie na ciasteczku sesji ustawionym przez control
// plane. Ciasteczko jest HttpOnly, wiec przegladarka dolacza je sama, ale
// zadania zmieniajace stan musza odeslac token CSRF z drugiego ciasteczka.

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

  /** Brak uwierzytelnienia wymaga przekierowania do logowania. */
  get unauthenticated() {
    return this.status === 401;
  }

  get forbidden() {
    return this.status === 403;
  }
}

function csrfToken(): string {
  const match = document.cookie
    .split("; ")
    .find((entry) => entry.startsWith(`${CSRF_COOKIE}=`));
  return match ? match.slice(CSRF_COOKIE.length + 1) : "";
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") {
    const token = csrfToken();
    if (token) headers[CSRF_HEADER] = token;
  }

  const response = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (response.status === 204) return undefined as T;

  const text = await response.text();
  const payload = text ? JSON.parse(text) : null;

  if (!response.ok) {
    throw new ApiError(
      response.status,
      payload?.code ?? "unknown",
      payload?.detail ?? response.statusText,
    );
  }
  return payload as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  del: <T>(path: string) => request<T>("DELETE", path),
};

export type Collection<T> = { items: T[]; count: number };
