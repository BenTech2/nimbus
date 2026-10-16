// API credential types (which fields each has) and the "Copy as …" formats.

/** Fields per credential type. `secret` fields are stored encrypted; the rest in plain data. */
export const API_KINDS = {
  apiKey: {
    label: 'API key',
    fields: [
      { id: 'key', label: 'API key', secret: true },
      { id: 'name', label: 'Header or parameter name', placeholder: 'X-API-Key' },
      { id: 'in', label: 'Send it as', options: [['header', 'Header'], ['query', 'Query parameter']] },
    ],
  },
  bearer: {
    label: 'Bearer token',
    fields: [
      { id: 'token', label: 'Token', secret: true },
      { id: 'refreshToken', label: 'Refresh token', secret: true, optional: true },
    ],
  },
  basic: {
    label: 'Basic auth',
    fields: [
      { id: 'username', label: 'Username' },
      { id: 'password', label: 'Password', secret: true },
    ],
  },
  oauth2: {
    label: 'OAuth 2.0',
    fields: [
      { id: 'clientId', label: 'Client ID' },
      { id: 'clientSecret', label: 'Client secret', secret: true },
      { id: 'tokenUrl', label: 'Token URL', placeholder: 'https://auth.example.com/oauth/token' },
      { id: 'authUrl', label: 'Authorization URL', optional: true },
      { id: 'scopes', label: 'Scopes', placeholder: 'read write', optional: true },
      { id: 'accessToken', label: 'Access token', secret: true, optional: true },
      { id: 'refreshToken', label: 'Refresh token', secret: true, optional: true },
    ],
  },
  custom: { label: 'Custom', fields: [] },
};

export const ENVIRONMENTS = ['Production', 'Staging', 'Development', 'Test', 'Local'];

/** Colour for an environment badge: production stands out, test-ish ones are calm. */
export function envColor(env) {
  const e = (env || '').toLowerCase();
  if (/prod|live/.test(e)) return 'var(--danger)';
  if (/stag|uat|pre/.test(e)) return 'var(--warn)';
  if (/dev|test|local|sandbox/.test(e)) return 'var(--ok)';
  return 'var(--muted)';
}

/** The field shown (masked) in the list: the key, token, password or client secret. */
export function primaryField(entry) {
  const want = { apiKey: 'key', bearer: 'token', basic: 'password', oauth2: 'clientSecret' }[entry.kind];
  return entry.fields.find((f) => f.id === want) || entry.fields.find((f) => f.secret) || null;
}

/** A non-secret detail worth showing next to the name: client id, username, header name. */
export function identity(entry) {
  const v = (id) => entry.fields.find((f) => f.id === id)?.value;
  if (entry.kind === 'oauth2') return v('clientId') ? `Client ${v('clientId')}` : '';
  if (entry.kind === 'basic') return v('username') || '';
  if (entry.kind === 'apiKey') return v('name') ? `${v('name')} ${v('in') === 'query' ? 'parameter' : 'header'}` : '';
  return '';
}

const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
const b64 = (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s)));
const envName = (s) => String(s || '').toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'API';

/** Which "Copy as" formats make sense for this credential. */
export function copyFormats(entry) {
  const has = (id) => entry.fields.some((f) => f.id === id);
  const out = [];
  if (['apiKey', 'bearer', 'basic'].includes(entry.kind) || (entry.kind === 'oauth2' && has('accessToken'))) out.push({ id: 'header', label: entry.kind === 'apiKey' && entry.fields.find((f) => f.id === 'in')?.value === 'query' ? 'Query string' : 'Authorization header' });
  if (entry.kind !== 'custom') out.push({ id: 'curl', label: entry.kind === 'oauth2' ? 'curl (get a token)' : 'curl command' });
  out.push({ id: 'env', label: '.env lines' }, { id: 'json', label: 'JSON' });
  return out;
}

/**
 * Build the text for a "Copy as" format. `get(fieldId)` resolves a field's value (revealing
 * secrets as needed) or null.
 */
export async function buildCopy(format, entry, get) {
  const url = entry.baseUrl || 'https://api.example.com';
  if (format === 'env' || format === 'json') {
    const prefix = envName(entry.service || entry.name);
    const pairs = [];
    for (const f of entry.fields) {
      const value = await get(f.id);
      if (value != null && value !== '') pairs.push([f.label || f.id, `${prefix}_${envName(f.label || f.id)}`, value]);
    }
    if (entry.baseUrl) pairs.unshift(['Base URL', `${prefix}_BASE_URL`, entry.baseUrl]);
    if (format === 'json') return JSON.stringify(Object.fromEntries(pairs.map(([label, , v]) => [label, v])), null, 2);
    return pairs.map(([, k, v]) => `${k}=${/[\s"'#$\\]/.test(v) ? JSON.stringify(v) : v}`).join('\n');
  }
  if (entry.kind === 'apiKey') {
    const name = (await get('name')) || 'X-API-Key';
    const key = (await get('key')) ?? '';
    const query = (await get('in')) === 'query';
    if (format === 'header') return query ? `${encodeURIComponent(name)}=${encodeURIComponent(key)}` : `${name}: ${key}`;
    return query ? `curl ${shq(`${url}${url.includes('?') ? '&' : '?'}${encodeURIComponent(name)}=${encodeURIComponent(key)}`)}` : `curl -H ${shq(`${name}: ${key}`)} ${shq(url)}`;
  }
  if (entry.kind === 'bearer' || entry.kind === 'oauth2') {
    if (entry.kind === 'oauth2' && format === 'curl') {
      const scopes = await get('scopes');
      return [
        `curl -X POST ${shq((await get('tokenUrl')) || `${url}/oauth/token`)}`,
        `  -u ${shq(`${(await get('clientId')) ?? ''}:${(await get('clientSecret')) ?? ''}`)}`,
        `  -d grant_type=client_credentials`,
        ...(scopes ? [`  -d ${shq(`scope=${scopes}`)}`] : []),
      ].join(' \\\n');
    }
    const token = (await get(entry.kind === 'bearer' ? 'token' : 'accessToken')) ?? '';
    if (format === 'header') return `Authorization: Bearer ${token}`;
    return `curl -H ${shq(`Authorization: Bearer ${token}`)} ${shq(url)}`;
  }
  if (entry.kind === 'basic') {
    const user = (await get('username')) ?? '';
    const pass = (await get('password')) ?? '';
    if (format === 'header') return `Authorization: Basic ${b64(`${user}:${pass}`)}`;
    return `curl -u ${shq(`${user}:${pass}`)} ${shq(url)}`;
  }
  return '';
}

/** "Expired 3 d ago" / "in 5 d" / a date, and how worried to be about it. */
export function expiryInfo(ms) {
  if (!ms) return null;
  const days = Math.round((ms - Date.now()) / 86400000);
  if (ms < Date.now()) return { text: days === 0 ? 'Expired today' : `Expired ${-days} d ago`, level: 'expired' };
  if (days <= 14) return { text: days === 0 ? 'Expires today' : `Expires in ${days} d`, level: 'soon' };
  return { text: new Date(ms).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }), level: 'ok' };
}
