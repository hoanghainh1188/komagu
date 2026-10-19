'use strict';

const { ResourceOperation } = require('../interfaces');

const KOMAINU_REQUIRE_OWNERSHIP_KEY = 'komainu:require_ownership';

// WeakMap fallback when reflect-metadata is not loaded
const metadataStore = new WeakMap();

function setMetadata(key, value, target) {
  if (!target || (typeof target !== 'object' && typeof target !== 'function')) return;
  if (typeof Reflect !== 'undefined' && typeof Reflect.defineMetadata === 'function') {
    Reflect.defineMetadata(key, value, target);
  }
  let targetMeta = metadataStore.get(target);
  if (!targetMeta) {
    targetMeta = new Map();
    metadataStore.set(target, targetMeta);
  }
  targetMeta.set(key, value);
}

function getMetadata(key, target) {
  if (!target || (typeof target !== 'object' && typeof target !== 'function')) return undefined;
  if (typeof Reflect !== 'undefined' && typeof Reflect.getMetadata === 'function') {
    const val = Reflect.getMetadata(key, target);
    if (val !== undefined) return val;
  }
  const targetMeta = metadataStore.get(target);
  if (targetMeta) {
    return targetMeta.get(key);
  }
  return undefined;
}

/**
 * Decorator attaching Komainu object ownership requirements to a NestJS controller or route handler.
 *
 * @param {string} operation - ResourceOperation ('Read', 'Create', 'Update', 'Delete')
 * @param {Object} options - { idParamName: 'id', resourceLoader: (id, req) => Promise<any> }
 */
function RequireOwnership(operation = ResourceOperation.READ, options = {}) {
  return function (target, propertyKey, descriptor) {
    const meta = {
      operation,
      idParamName: options.idParamName || 'id',
      resourceLoader: options.resourceLoader,
      options,
    };

    if (descriptor && descriptor.value) {
      setMetadata(KOMAINU_REQUIRE_OWNERSHIP_KEY, meta, descriptor.value);
      return descriptor;
    }
    setMetadata(KOMAINU_REQUIRE_OWNERSHIP_KEY, meta, target);
    return target;
  };
}

/**
 * Parameter decorator extracting the verified user principal from the request.
 */
function CurrentUser() {
  return function (target, propertyKey, parameterIndex) {
    const existing = getMetadata('komainu:current_user_indices', target) || [];
    existing.push(parameterIndex);
    setMetadata('komainu:current_user_indices', existing, target);
  };
}

module.exports = {
  KOMAINU_REQUIRE_OWNERSHIP_KEY,
  RequireOwnership,
  CurrentUser,
  setMetadata,
  getMetadata,
};
