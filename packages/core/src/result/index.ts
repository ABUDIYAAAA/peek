export type SuccessTuple<T> = [error: null, data: T];
export type ErrorTuple<E = Error> = [error: E, data: null];
export type TryCatchTuple<T, E = Error> = SuccessTuple<T> | ErrorTuple<E>;

export type Result<T, E = Error> =
  | { readonly ok: true; readonly value: T; readonly error?: never }
  | { readonly ok: false; readonly error: E; readonly value?: never };

export function ok<T>(value: T): Result<T, never> {
  return { ok: true, value };
}

export function err<E>(error: E): Result<never, E> {
  return { ok: false, error };
}

export function isOk<T, E>(
  result: Result<T, E>,
): result is { ok: true; value: T; error?: never } {
  return result.ok;
}

export function isErr<T, E>(
  result: Result<T, E>,
): result is { ok: false; error: E; value?: never } {
  return !result.ok;
}

/**
 * Executes an async operation or resolves a promise safely without throwing.
 * Returns `[null, data]` on success or `[error, null]` on failure.
 *
 * Example:
 * ```ts
 * const [err, user] = await tryCatch(fetchUser(id));
 * if (err) return handleErr(err);
 * ```
 */
export async function tryCatch<T, E = Error>(
  promiseOrFn: Promise<T> | (() => Promise<T> | T),
): Promise<TryCatchTuple<T, E>> {
  try {
    const promise =
      typeof promiseOrFn === "function" ? promiseOrFn() : promiseOrFn;
    const data = await promise;
    return [null, data];
  } catch (rawError) {
    const error = (
      rawError instanceof Error ? rawError : new Error(String(rawError))
    ) as E;
    return [error, null];
  }
}

/**
 * Executes a synchronous function safely without throwing.
 * Returns `[null, data]` on success or `[error, null]` on failure.
 */
export function tryCatchSync<T, E = Error>(fn: () => T): TryCatchTuple<T, E> {
  try {
    const data = fn();
    return [null, data];
  } catch (rawError) {
    const error = (
      rawError instanceof Error ? rawError : new Error(String(rawError))
    ) as E;
    return [error, null];
  }
}

/**
 * Wraps a promise or function into a Result object { ok: true, value } | { ok: false, error }.
 */
export async function resultify<T, E = Error>(
  promiseOrFn: Promise<T> | (() => Promise<T> | T),
): Promise<Result<T, E>> {
  const [error, data] = await tryCatch<T, E>(promiseOrFn);
  if (error !== null) {
    return err(error);
  }
  return ok(data as T);
}
