export class ApiError extends Error { constructor(message: string, readonly status: number) { super(message); } }
let refreshing: Promise<boolean> | null = null;
function csrf() { return document.cookie.split('; ').find(value => value.startsWith('sg_csrf='))?.slice(8) || ''; }

export async function api<T = unknown>(path: string, method = 'GET', body?: unknown, retry = true): Promise<T> {
  const response = await fetch(`/api${path}`, { method, credentials: 'same-origin', cache: 'no-store', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (response.status === 401 && retry && !['/auth/login', '/auth/register', '/auth/refresh'].includes(path)) {
    if (!refreshing) {
      refreshing = fetch('/api/auth/refresh', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() }, body: '{}' }).then(result => result.ok).finally(() => { refreshing = null; });
    }
    if (await refreshing) return api<T>(path, method, body, false);
  }
  const data = await response.json().catch(() => ({ message: 'The server returned an unreadable response' }));
  if (!response.ok) throw new ApiError(data.message || 'Request failed', response.status);
  return data as T;
}
