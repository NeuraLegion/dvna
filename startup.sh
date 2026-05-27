#! /bin/bash
set -e

if [ -d /app/node_modules ]; then
  find /app/node_modules -mindepth 1 -maxdepth 1 ! -name '.package-lock.json' -exec rm -rf {} + || true
fi

npm ci
npm rebuild bcrypt --build-from-source || npm install bcrypt --build-from-source
exec nodemon server.js
