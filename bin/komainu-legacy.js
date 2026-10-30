#!/usr/bin/env node
/**
 * Deprecated `komainu` / `komainu-guard` npm bin aliases.
 *
 * Prints a rename notice to stderr, then runs the Komagu launcher unchanged.
 * Remove in the next major release (#290).
 */

'use strict';

console.error(
  '\x1b[33m[DEPRECATED]\x1b[0m `komainu` / `komainu-guard` were renamed to `komagu`. ' +
  'Install @hoanghainh/komagu and run `komagu` instead.'
);

require('./komagu.js');
