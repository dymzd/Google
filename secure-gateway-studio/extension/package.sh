#!/usr/bin/env sh
# Build and package. Produces dist/ (load unpacked) and a versioned
# secure-gateway-studio-<manifest-version>.zip (Chrome Web Store).
set -e
node build.mjs
python package.py
