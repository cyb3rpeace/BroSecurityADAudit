#!/bin/sh
set -eu
cd "$(dirname "$0")"
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/workspace" -w /workspace node:22-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d sh -lc 'npm ci --no-audit --no-fund && npm run build'
