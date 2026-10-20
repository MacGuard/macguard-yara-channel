// The only place that talks to the server. A 401 anywhere in the app is announced so the shell can show the right sign-in state.
let csrf = '';
export const setCsrf = (v) => { csrf = v || ''; };
export async function api(method, path, body) {
  let r;
  try {
    r = await fetch(path, { method, credentials: 'same-origin', headers: { Accept: 'application/json', ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(method !== 'GET' && csrf ? { 'X-CSRF-Token': csrf } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch { return { status: 0, data: {}, network: true }; }
  let data = {}; try { data = await r.json(); } catch { /* empty or non-JSON body */ }
  if (r.status === 401) window.dispatchEvent(new CustomEvent('mg:unauth', { detail: data.code || 'signin' }));
  return { status: r.status, data, network: false };
}
export const failure = (r, fallback) => (r.network ? fallback : (r.data && r.data.error) || fallback);
