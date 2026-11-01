/**
 * Returns a new plain object holding only the allow-listed own enumerable keys of `source`.
 * `__proto__`, `constructor` and `prototype` are always ignored; non-object source yields `{}`.
 */
export declare function allowFields<T extends object, K extends string>(
  source: T | null | undefined,
  allowed: readonly K[]
): Partial<Pick<T, Extract<K, keyof T>>>;
