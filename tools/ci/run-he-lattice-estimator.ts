import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const estimatorDirectoryPath = path.resolve(
    repoRoot,
    'reference-projects',
    'lattice-estimator',
);
const expectedEstimatorCommit = '27a581bb8e9d49f5e9e2db315bd48ac769d5f5f5';

const pythonEstimatorScript = String.raw`
import json
from sys import path as sys_path

sys_path.insert(0, "/estimator")

from estimator import LWE, ND, RC
from estimator.lwe_parameters import LWEParameters
from estimator.reduction import ADPS16
from sage.all import RR, log, oo

DATA_PRIMES = [
    140737487306753,
    140737486716929,
    140737486520321,
    140737485864961,
    140737484685313,
    140737483898881,
    140737482981377,
    140737481801729,
    140737481342977,
    140737480949761,
    140737480359937,
    140737479639041,
    140737476100097,
    140737472299009,
    140737471971329,
    140737471774721,
    140737471578113,
]
SPECIAL_PRIME = 140737471512577
TARGET_CLASSICAL_SECURITY_BITS = 128.0


def product(values):
    result = 1
    for value in values:
        result *= value
    return result


def exact_log2_ceil(value):
    if value & (value - 1) == 0:
        return value.bit_length() - 1
    return value.bit_length()


def log2_value(value):
    return float(RR(log(value, 2)))


def copy_integer(result, row, source_key, target_key=None):
    if source_key in result:
        row[target_key or source_key] = int(result[source_key])


def copy_log2(result, row, source_key, target_key):
    if source_key in result:
        row[target_key] = log2_value(result[source_key])


def estimate_attack_rows(parameters, reduction_cost_model):
    bdd = LWE.primal_bdd(parameters, red_cost_model=reduction_cost_model)
    dual = LWE.dual(parameters, red_cost_model=reduction_cost_model)
    dual_hybrid = LWE.dual_hybrid(parameters, red_cost_model=reduction_cost_model)
    usvp = LWE.primal_usvp(parameters, red_cost_model=reduction_cost_model)

    rows = {}

    bdd_row = {}
    for key in ["beta", "d", "eta"]:
        copy_integer(bdd, bdd_row, key)
    copy_log2(bdd, bdd_row, "red", "redLog2")
    copy_log2(bdd, bdd_row, "rop", "ropLog2")
    copy_log2(bdd, bdd_row, "svp", "svpLog2")
    rows["bdd"] = bdd_row

    dual_row = {}
    for key in ["beta", "d", "m"]:
        copy_integer(dual, dual_row, key)
    copy_log2(dual, dual_row, "mem", "memLog2")
    copy_log2(dual, dual_row, "rop", "ropLog2")
    rows["dual"] = dual_row

    dual_hybrid_row = {}
    for key in ["beta", "m", "p", "t", "zeta"]:
        copy_integer(dual_hybrid, dual_hybrid_row, key)
    copy_integer(dual_hybrid, dual_hybrid_row, "beta_", "beta_")
    copy_log2(dual_hybrid, dual_hybrid_row, "N", "NLog2")
    copy_log2(dual_hybrid, dual_hybrid_row, "guess", "guessLog2")
    copy_log2(dual_hybrid, dual_hybrid_row, "red", "redLog2")
    copy_log2(dual_hybrid, dual_hybrid_row, "rop", "ropLog2")
    rows["dual_hybrid"] = dual_hybrid_row

    usvp_row = {}
    for key in ["beta", "d"]:
        copy_integer(usvp, usvp_row, key)
    copy_log2(usvp, usvp_row, "red", "redLog2")
    copy_log2(usvp, usvp_row, "rop", "ropLog2")
    rows["usvp"] = usvp_row

    return rows


def estimate_parameter_set(
    modulus,
    secret_distribution,
    error_distribution,
    tag,
    reduction_cost_model=RC.MATZOV,
):
    parameters = LWEParameters(
        n=32768,
        q=modulus,
        Xs=secret_distribution,
        Xe=error_distribution,
        m=oo,
        tag=tag,
    )
    rows = estimate_attack_rows(parameters, reduction_cost_model)
    weakest_attack, weakest_row = min(
        rows.items(),
        key=lambda row: row[1]["ropLog2"],
    )
    weakest_cost = weakest_row["ropLog2"]
    return {
        "modulusCeilLog2": exact_log2_ceil(modulus),
        "modulusLog2": log2_value(modulus),
        "weakestAttack": weakest_attack,
        "weakestAttackCostLog2": weakest_cost,
        "marginTo128Bits": weakest_cost - TARGET_CLASSICAL_SECURITY_BITS,
        "rows": rows,
    }


def estimate_quantum_context_parameter_set(
    modulus,
    secret_distribution,
    error_distribution,
    tag,
):
    row = estimate_parameter_set(
        modulus,
        secret_distribution,
        error_distribution,
        tag,
        ADPS16(mode="quantum"),
    )
    row["costModel"] = "ADPS16(mode=quantum)"
    row["rowScope"] = (
        "quantum-leaning context only; setup/evaluator closure remains the "
        "currentQDataCenteredBinomialEta2 RC.MATZOV classical row"
    )
    row["marginToConventional128Bits"] = (
        row["weakestAttackCostLog2"] - TARGET_CLASSICAL_SECURITY_BITS
    )
    del row["marginTo128Bits"]
    return row


q_data = product(DATA_PRIMES)
q_extended = q_data * SPECIAL_PRIME

output = {
    "objectType": "SealedLatticeHeLatticeEstimatorRun",
    "objectVersion": 1,
    "estimatorRepository": "https://github.com/malb/lattice-estimator",
    "estimatorCommit": "27a581bb8e9d49f5e9e2db315bd48ac769d5f5f5",
    "estimatorDefaultCostModel": "RC.MATZOV",
    "sageRuntime": "SageMath 10.9",
    "dockerImage": "sagemath/sagemath:latest",
    "command": "pnpm exec tsx ./tools/ci/run-he-lattice-estimator.ts",
    "inputParameters": {
        "polynomialDegree": 32768,
        "dataPrimes": DATA_PRIMES,
        "specialPrime": SPECIAL_PRIME,
        "secretDistribution": "ND.Ternary",
        "currentErrorDistribution": "ND.CenteredBinomial(2)",
        "referenceErrorDistribution": "ND.DiscreteGaussian(3.19)",
        "quantumLeaningContextCostModel": "ADPS16(mode=quantum)",
        "sampleModel": "m=+Infinity",
    },
    "results": {
        "bcc25ReferenceTwoPower868Gaussian319": estimate_parameter_set(
            2**868,
            ND.Ternary,
            ND.DiscreteGaussian(3.19),
            "bcc25-reference-two-power-868-gaussian-319",
        ),
        "boundaryTwoPower868CenteredBinomialEta2": estimate_parameter_set(
            2**868,
            ND.Ternary,
            ND.CenteredBinomial(2),
            "boundary-two-power-868-centered-binomial-eta2",
        ),
        "boundaryTwoPower881CenteredBinomialEta2": estimate_parameter_set(
            2**881,
            ND.Ternary,
            ND.CenteredBinomial(2),
            "boundary-two-power-881-centered-binomial-eta2",
        ),
        "currentQDataCenteredBinomialEta2": estimate_parameter_set(
            q_data,
            ND.Ternary,
            ND.CenteredBinomial(2),
            "current-q-data-centered-binomial-eta2",
        ),
        "currentQDataCenteredBinomialEta2Adps16QuantumSieveContext": estimate_quantum_context_parameter_set(
            q_data,
            ND.Ternary,
            ND.CenteredBinomial(2),
            "current-q-data-centered-binomial-eta2-adps16-quantum-sieve-context",
        ),
        "qExtendedIfExposedCenteredBinomialEta2": estimate_parameter_set(
            q_extended,
            ND.Ternary,
            ND.CenteredBinomial(2),
            "q-extended-if-exposed-centered-binomial-eta2",
        ),
    },
}

print(json.dumps(output, indent=2))
`;

const assertPinnedEstimatorCheckout = (): void => {
    const result = spawnSync(
        'git',
        ['-C', estimatorDirectoryPath, 'rev-parse', 'HEAD'],
        {
            encoding: 'utf8',
            maxBuffer: 1024 * 1024,
        },
    );

    if (result.error !== undefined) {
        throw new Error(
            `Failed to inspect lattice-estimator checkout: ${result.error.message}`,
        );
    }
    if (result.status !== 0) {
        throw new Error(
            `lattice-estimator checkout is missing or unreadable at ${estimatorDirectoryPath}`,
        );
    }

    const actualCommit = result.stdout.trim();
    if (actualCommit !== expectedEstimatorCommit) {
        throw new Error(
            `Expected lattice-estimator ${expectedEstimatorCommit}, got ${actualCommit}`,
        );
    }
};

const runEstimator = (): string => {
    const result = spawnSync(
        'docker',
        [
            'run',
            '--rm',
            '-i',
            '-v',
            `${estimatorDirectoryPath}:/estimator:ro`,
            '-w',
            '/estimator',
            'sagemath/sagemath:latest',
            'sage',
            '-python',
            '-',
        ],
        {
            encoding: 'utf8',
            input: pythonEstimatorScript,
            maxBuffer: 100 * 1024 * 1024,
        },
    );

    if (result.stderr !== undefined && result.stderr !== '') {
        process.stderr.write(result.stderr);
    }
    if (result.error !== undefined) {
        throw new Error(
            `Failed to run Dockerized Sage: ${result.error.message}`,
        );
    }
    if (result.status !== 0) {
        throw new Error(
            `Dockerized Sage estimator exited with status ${result.status ?? 'null'}`,
        );
    }

    return result.stdout;
};

type JsonValue =
    | boolean
    | null
    | number
    | string
    | readonly JsonValue[]
    | { readonly [key: string]: JsonValue };

const sortJsonValue = (value: JsonValue): JsonValue => {
    if (Array.isArray(value)) {
        return value.map(sortJsonValue);
    }
    if (typeof value === 'object' && value !== null) {
        return Object.fromEntries(
            Object.entries(value)
                .sort(([left], [right]) => left.localeCompare(right))
                .map(([key, nestedValue]) => [key, sortJsonValue(nestedValue)]),
        );
    }

    return value;
};

const parseJson = (jsonText: string): JsonValue =>
    JSON.parse(jsonText) as JsonValue;

const normalizeJsonText = (jsonText: string): string =>
    `${JSON.stringify(sortJsonValue(parseJson(jsonText)), null, 2)}\n`;

const main = (): void => {
    assertPinnedEstimatorCheckout();
    process.stdout.write(normalizeJsonText(runEstimator()));
};

if (isDirectlyInvokedModule(import.meta.url)) {
    main();
}
