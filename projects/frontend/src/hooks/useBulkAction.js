import { useCallback, useEffect, useRef, useState } from 'react';

// Confirm-then-run state for bulk actions on "all results" selections, which can touch hundreds
// of thousands of rows from a single keypress.
//   bulk = null
//        | { phase: 'confirm', message, ... }      waiting for Enter / Esc
//        | { phase: 'running', label, done, total } work in progress
//        | { phase: 'done' | 'error', message }   result, dismissed with Esc or after a few seconds
export const useBulkAction = () => {
  const [bulk, setBulkState] = useState(null);
  const ref = useRef(null);
  const setBulk = useCallback((next) => {
    ref.current = typeof next === 'function' ? next(ref.current) : next;
    setBulkState(ref.current);
  }, []);

  // Ask for confirmation. `work(progress)` does the job, calling progress(count) as it goes, and
  // resolves to the number of rows handled; `doneMessage(n)` describes the result; `onFinish`
  // runs afterwards whether the work succeeded or failed.
  const ask = useCallback(({ message, label, total, work, doneMessage, onFinish }) => {
    const phase = ref.current?.phase;
    if (phase === 'running' || phase === 'confirm') return;
    setBulk({ phase: 'confirm', message, label, total, work, doneMessage, onFinish });
  }, [setBulk]);

  const confirm = useCallback(async () => {
    const b = ref.current;
    if (!b || b.phase !== 'confirm') return;
    setBulk({ phase: 'running', label: b.label, total: b.total, done: 0 });
    try {
      const n = await b.work((count) => setBulk((cur) => (cur?.phase === 'running' ? { ...cur, done: cur.done + count } : cur)));
      setBulk({ phase: 'done', message: b.doneMessage(n) });
    } catch (err) {
      console.error('Bulk action failed:', err);
      setBulk({ phase: 'error', message: `Failed: ${err.message}` });
    } finally {
      b.onFinish?.();
    }
  }, [setBulk]);

  const cancel = useCallback(() => {
    if (ref.current && ref.current.phase !== 'running') setBulk(null);
  }, [setBulk]);

  // Hide a success message after a few seconds (errors stay until dismissed)
  useEffect(() => {
    if (bulk?.phase !== 'done') return undefined;
    const timer = setTimeout(() => setBulk((cur) => (cur?.phase === 'done' ? null : cur)), 5000);
    return () => clearTimeout(timer);
  }, [bulk, setBulk]);

  // Keyboard: while confirming, Enter runs and Esc cancels, and every other key is swallowed so it
  // can't act on the list behind the prompt. Returns true when the key was consumed.
  const handleKey = useCallback((e) => {
    const b = ref.current;
    if (!b) return false;
    if (b.phase === 'confirm') {
      e.preventDefault();
      if (e.key === 'Enter') confirm();
      else if (e.key === 'Escape') cancel();
      return true;
    }
    if ((b.phase === 'done' || b.phase === 'error') && e.key === 'Escape') {
      e.preventDefault();
      cancel();
      return true;
    }
    return false;
  }, [cancel, confirm]);

  const isBusy = useCallback(() => ref.current?.phase === 'running' || ref.current?.phase === 'confirm', []);

  return { bulk, ask, confirm, cancel, handleKey, isBusy };
};
