#!/usr/bin/env node
/**
 * Komagu CLI — Node.js Bridge Launcher for npm / npx execution.
 *
 * Forwards arguments and streams directly to the Komagu Python CLI engine.
 */

'use strict';

const { spawn, spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

function findPythonBinary() {
  if (process.env.PYTHON_BIN) {
    return fs.existsSync(process.env.PYTHON_BIN) ? process.env.PYTHON_BIN : null;
  }

  const candidates = process.platform === 'win32'
    ? ['python', 'py', 'python3']
    : ['python3', 'python'];

  for (const bin of candidates) {
    try {
      const check = spawnSync(bin, ['--version'], {
        stdio: 'ignore',
        encoding: 'utf-8',
        shell: false,
      });
      if (check.status === 0) {
        return bin;
      }
    } catch (_) {
      // Continue checking next candidate
    }
  }
  return null;
}

function showPythonMissingError() {
  console.error('\x1b[31m\x1b[1m[ERROR]\x1b[0m Python 3.8+ is required to execute Komagu CLI.');
  console.error('Please install Python 3 from https://www.python.org/downloads/');
  console.error('');
  console.error('Alternatively, run via the zero-install Docker container image:');
  console.error('  docker run --rm -v $(pwd):/workspace ghcr.io/hoanghainh1188/komainu scan /workspace');
}

function main() {
  const pythonBin = findPythonBinary();
  const scriptPath = path.join(__dirname, 'komagu');

  if (!pythonBin) {
    showPythonMissingError();
    process.exit(1);
  }

  if (!fs.existsSync(scriptPath)) {
    console.error(`\x1b[31m\x1b[1m[ERROR]\x1b[0m Komagu engine script not found at ${scriptPath}`);
    process.exit(1);
  }

  const args = [scriptPath, ...process.argv.slice(2)];
  const child = spawn(pythonBin, args, {
    stdio: 'inherit',
    env: process.env,
  });

  child.on('error', (err) => {
    if (err.code === 'ENOENT') {
      showPythonMissingError();
    } else {
      console.error('\x1b[31m[ERROR]\x1b[0m Failed to spawn Komagu process:', err.message);
    }
    process.exit(1);
  });

  child.on('close', (code, signal) => {
    if (signal) {
      process.exit(1);
    }
    process.exit(code !== null ? code : 0);
  });
}

main();
