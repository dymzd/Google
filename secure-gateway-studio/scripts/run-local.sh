#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
frontend_dir="${project_root}/frontend"
backend_python="${project_root}/backend/.venv/bin/python"
backend_uvicorn="${project_root}/backend/.venv/bin/uvicorn"

if [[ -f "${project_root}/.env.local" ]]; then
  set -a
  source "${project_root}/.env.local"
  set +a
fi

if [[ ! -x "${backend_python}" || ! -x "${backend_uvicorn}" ]]; then
  echo "Backend environment is missing. Follow the installation steps in README.md." >&2
  exit 1
fi

if [[ ! -d "${frontend_dir}/node_modules" ]]; then
  echo "Frontend dependencies are missing. Run 'pnpm install --frozen-lockfile' in frontend/." >&2
  exit 1
fi

(
  cd "${frontend_dir}"
  pnpm build
)

cd "${project_root}"
exec "${backend_uvicorn}" \
  --app-dir "${project_root}/backend/src" \
  sgstudio.api.main:app \
  --host 127.0.0.1 \
  --port 8787
