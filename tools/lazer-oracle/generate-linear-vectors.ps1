param(
    [string]$ImageName = $(if ($env:LAZER_ORACLE_IMAGE) { $env:LAZER_ORACLE_IMAGE } else { "sealed-lattice-lazer-oracle:local" })
)

$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $true
}

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptRoot "..\..")
$DockerfileDirectory = Join-Path $RepoRoot "tools\lazer-oracle"

docker build -t $ImageName $DockerfileDirectory
if ($LASTEXITCODE -ne 0) {
    throw "Docker image build failed for the LaZer oracle."
}

docker run --rm `
    -v "${RepoRoot}:/work" `
    -w /work/temp/lazer `
    $ImageName `
    bash -lc "set -euo pipefail && make -B lazer.h && test -s lazer.h && test -s python/demo/demo_params.h && make liblazer.so && cd python && make && cd demo && python3 ../params_cffi_build.py demo_params.h ../.. && python3 /work/tools/lazer-oracle/vector-emitter/emit_linear_vectors.py --repo-root /work --lazer-root /work/temp/lazer --out /work/test-vectors/ballot-privacy/proof-backend-linear-vectors.json"
if ($LASTEXITCODE -ne 0) {
    throw "LaZer oracle vector generation failed."
}
