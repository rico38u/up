#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
[ -d node_modules ] || npm install
[ -f .env ] || cp .env.example .env
node server.js
