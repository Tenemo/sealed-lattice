#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image_name="${LAZER_ORACLE_IMAGE:-sealed-lattice-lazer-oracle:local}"

docker build -t "${image_name}" "${repo_root}/tools/lazer-oracle"

docker run --rm \
  -v "${repo_root}:/work" \
  -w /work/temp/lazer \
  "${image_name}" \
  bash -lc '
    set -euo pipefail
    make -B lazer.h
    test -s lazer.h
    test -s python/demo/demo_params.h
    make liblazer.so
    cd python
    make
    cd demo
    python3 ../params_cffi_build.py demo_params.h ../..
    python3 /work/tools/lazer-oracle/vector-emitter/emit_linear_vectors.py \
      --repo-root /work \
      --lazer-root /work/temp/lazer \
      --out /work/test-vectors/ballot-privacy/proof-backend-linear-vectors.json
  '
