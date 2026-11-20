import { createClient } from 'graphql-ws';
import { useEffect, useRef } from 'react';

// One shared websocket for the list pages' change signals
let client = null;
const getClient = () => {
  if (!client) {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    client = createClient({
      url: `${wsProtocol}//${window.location.host}/hasura/v1/graphql`,
      lazy: true,
      connectionParams: {
        headers: { 'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET },
      },
    });
  }
  return client;
};

/**
 * Subscribe to a few tiny aggregate queries (e.g. a table's max id / count) and call `onChange`
 * when any of their results changes, so a list can refetch just its current page instead of
 * streaming the whole result set. Calls are debounced (trailing) and spaced at least
 * `minIntervalMs` apart. The first result of each subscription only sets the baseline.
 *
 * `queries` must be stable strings (one root field each: Hasura subscriptions allow only one).
 */
export const useChangeSignal = (queries, onChange, { debounceMs = 800, minIntervalMs = 2500, enabled = true } = {}) => {
  const onChangeRef = useRef(onChange);
  // eslint-disable-next-line react-hooks/refs -- latest-value ref so the subscription never goes stale
  onChangeRef.current = onChange;
  const key = queries.join('\n');

  useEffect(() => {
    if (!enabled) return undefined;
    const last = {};
    let timer = null;
    let lastFired = 0;

    const schedule = () => {
      if (timer) clearTimeout(timer);
      const wait = Math.max(debounceMs, lastFired + minIntervalMs - Date.now());
      timer = setTimeout(() => {
        timer = null;
        lastFired = Date.now();
        onChangeRef.current?.();
      }, wait);
    };

    const unsubscribers = queries.map((query, i) =>
      getClient().subscribe(
        { query },
        {
          next: ({ data }) => {
            const value = JSON.stringify(data);
            if (i in last && last[i] !== value) schedule();
            last[i] = value;
          },
          error: (err) => console.error('Change-signal subscription error:', err),
          complete: () => {},
        },
      ),
    );

    return () => {
      if (timer) clearTimeout(timer);
      unsubscribers.forEach((unsubscribe) => unsubscribe());
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, enabled, debounceMs, minIntervalMs]);
};
