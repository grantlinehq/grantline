export type User = {
  id: string;
  email: string;
  name: string;
  role: string;
  mfa_pending: boolean;
  disabled?: boolean;
};
export type Status = {
  mode: string;
  setup_required: boolean;
  organization: string;
  oidc_enabled: boolean;
  email_enabled?: boolean;
};
let csrf = "";
export class APIError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}
export function setCSRF(value: string) {
  csrf = value;
}
export async function api<T = any>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const response = await fetch(`/api/v1${path}`, {
    method,
    credentials: "same-origin",
    headers: {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(method !== "GET" ? { "X-Grantline-CSRF": csrf } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok)
    throw new APIError(
      (data.error || `Request failed (${response.status})`).replaceAll(
        "_",
        " ",
      ),
      response.status,
    );
  return data as T;
}
export const when = (value?: string) =>
  value
    ? new Date(value).toLocaleString("en-GB", {
        day: "numeric",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "Not yet";
