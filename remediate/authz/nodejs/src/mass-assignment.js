'use strict';

const BLOCKED_KEYS = Object.freeze(['__proto__', 'constructor', 'prototype']);

/**
 * Mass-assignment guard: copy only allow-listed own enumerable keys.
 *
 * - Returns a NEW plain object; `source` is never mutated.
 * - Keys missing from `source` are skipped (not set to undefined).
 * - `__proto__`, `constructor` and `prototype` are always ignored.
 * - Non-object (or array) `source` yields `{}`.
 * - Values are copied by reference (shallow copy).
 *
 * @param {Object} source - untrusted input such as req.body
 * @param {string[]} allowed - field names the caller may set
 * @returns {Object}
 */
function allowFields(source, allowed) {
  if (!Array.isArray(allowed)) {
    throw new TypeError('allowFields: allowed must be an array of field names');
  }
  const result = {};
  if (source === null || typeof source !== 'object' || Array.isArray(source)) {
    return result;
  }
  for (const key of allowed) {
    if (typeof key !== 'string' || BLOCKED_KEYS.includes(key)) {
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(source, key) &&
        Object.prototype.propertyIsEnumerable.call(source, key)) {
      result[key] = source[key];
    }
  }
  return result;
}

module.exports = {
  allowFields,
};
