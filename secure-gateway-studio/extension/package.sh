#!/usr/bin/env sh
# Build and package. Produces dist/ (load unpacked), dist.zip (Web Store).
set -e
node build.mjs
python package.py
