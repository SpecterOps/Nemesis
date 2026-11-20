// Small helpers for talking to Hasura from pages that don't need a full client.
import { createClient } from 'graphql-ws';

/**
 * POST a GraphQL query to Hasura and return `data`, throwing on HTTP or GraphQL errors.
 * @param {string} query
 * @param {Record<string, any>} [variables]
 * @param {{ signal?: AbortSignal }} [options]
 */
export async function hasuraQuery(query, variables = {}, { signal } = {}) {
  const response = await fetch('/hasura/v1/graphql', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
    },
    body: JSON.stringify({ query, variables }),
    signal,
  });
  if (!response.ok) throw new Error(`Network response error: ${response.status}`);
  const result = await response.json();
  if (result.errors) throw new Error(result.errors[0].message);
  return result.data;
}

let sharedWsClient = null;

/**
 * Lazily-created graphql-ws client shared by the components that use these helpers.
 * graphql-ws is lazy by default: the socket closes when no subscriptions remain.
 */
export function getHasuraWsClient() {
  if (!sharedWsClient) {
    sharedWsClient = createClient({
      url: `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/hasura/v1/graphql`,
      connectionParams: {
        headers: {
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
      },
    });
  }
  return sharedWsClient;
}

/**
 * Subscribe to a tiny "change signal" (e.g. max(id) aggregates) and invoke `onChange`
 * (debounced) whenever the signal's payload changes. The first payload also triggers
 * `onChange` so callers can rely on it for the initial load.
 *
 * `queries` may be a single subscription document or an array of them (GraphQL subscriptions
 * allow only one root field, so watching several tables needs several subscriptions). With an
 * array, `onChange` fires once every subscription has delivered its first payload, then on any
 * subsequent change.
 *
 * Use this instead of subscribing to large result sets: Hasura re-runs the signal query
 * cheaply (index-only max/min lookups) and only a few bytes cross the websocket.
 *
 * Returns an unsubscribe function.
 * @param {string | string[]} queries
 * @param {(data: any) => void} onChange
 * @param {{ debounceMs?: number, variables?: Record<string, any>, onError?: (error: any) => void }} [options]
 * @returns {() => void}
 */
export function subscribeToChangeSignal(queries, onChange, { debounceMs = 1000, variables = {}, onError } = {}) {
  const list = Array.isArray(queries) ? queries : [queries];
  const latest = new Array(list.length).fill(null);
  let initialised = false;
  let timer = null;

  const unsubscribers = list.map((query, idx) =>
    getHasuraWsClient().subscribe(
      { query, variables },
      {
        next(result) {
          if (!result?.data) return;
          const key = JSON.stringify(result.data);
          if (key === latest[idx]) return;
          latest[idx] = key;
          if (latest.some(v => v === null)) return;
          const merged = Object.assign({}, ...latest.map(v => JSON.parse(v)));
          if (!initialised) {
            initialised = true;
            onChange(merged);
            return;
          }
          clearTimeout(timer);
          timer = setTimeout(() => onChange(merged), debounceMs);
        },
        error(err) {
          if (onError) onError(err);
          else console.error('Change-signal subscription error:', err);
        },
        complete() {},
      }
    )
  );
  return () => {
    clearTimeout(timer);
    unsubscribers.forEach(u => u());
  };
}
