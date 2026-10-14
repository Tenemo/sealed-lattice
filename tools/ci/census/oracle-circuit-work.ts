import { compileSignatureHashInputs } from '#tests/authentication-work-model.js';
import {
    prefixOracleWork,
    oracleMaskRoutingWork,
} from '#tests/compressed-oracle/oracle-access.js';
import { labelledHashExtractionWork } from '#tests/compressed-oracle/source-extraction.js';
import { sparseRoutingWork } from '#tests/compressed-oracle/sparse-routing.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import {
    compileClassicalReaderOracleBudget,
    compileFullCircuitOracleBudget,
    compileOraclePermutationBudget,
    shakePermutationGateCharge,
} from '#tests/oracle-budget-model.js';
import {
    oracleDomainWork,
    programmedOracleDomainWork,
    shadowOracleDomainWork,
} from '#tests/oracle-domain-model.js';
import { sourceOpeningSaltBytes } from '#tests/registration-setup-binding-model.js';
import { minimumRegistrationSourceInputBytes } from '#tests/registration-source-domain-model.js';
import {
    compileRegistrationSourceExtractionWork,
    compileRegistrationSourceRandomness,
} from '#tests/registration-source-randomness-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';
import { formatCount, table } from '#tools/ci/census/format.js';
import { maximumFirstOracleResumeFactor } from '#tools/ci/census/proof-hash-work.js';

export const renderCompressedOracleCircuitWork = (): string[] => {
    const completion = completionProfile();
    const maximumFirstOracleResume = maximumFirstOracleResumeFactor();
    const registrationSourceRandomness = compileRegistrationSourceRandomness(
        completion.participantCount,
        completion.optionCount,
    );
    return [
        '## Compressed-oracle circuit work',
        '',
        "The declared gate basis is X, CNOT, Toffoli and controlled-H, each acting on at most three qubits. The sorted database uses one spare tuple while routing the queried value to a separate register. Clean computation includes inverse evaluation and register swaps. These bounded examples verify the circuit family; they are not the protocol's full input domain or query population.",
        '',
        table(
            [
                'Prior queries',
                'Input bits',
                'Hash bits',
                'Removal compute gates',
                'Insertion compute gates',
                'Clean routing gates',
                'Oracle-call gates',
                'Oracle qubits',
                'Constructed tuple-index words',
            ],
            [
                [0n, 2n, 1n],
                [1n, 2n, 1n],
                [2n, 2n, 1n],
                [1n, 1n, 2n],
            ].map(([prior, input, output]) => {
                const work = sparseRoutingWork(prior, input, output);
                return [
                    prior,
                    input,
                    output,
                    work.removeGates,
                    work.insertGates,
                    work.routingGates,
                    work.roundTripRoutingGates + work.localUpdateGates,
                    work.routingQubits + output,
                    work.constructorTupleIndexWords,
                ].map(formatCount);
            }),
        ),
        '',
        'Tuple-index words count the row arrays constructed by the sparse routing emitter. Direct column indexing removes the repeated row materialization inside output-bit selection. This is a constructor allocation operand, not a bit-operation, dispatch, or complete construction-time bound; emitted gates are unchanged.',
        '',
        table(
            [
                'Local hash output bits',
                'Controlled-H gates',
                'X gates',
                'CNOT gates',
                'Toffoli gates',
                'Total local update gates',
            ],
            [1n, 2n, 3n, 512n].map((bits) => {
                const work = sparseRoutingWork(0n, 1n, bits);
                return [
                    bits,
                    work.localUpdate.controlledHadamard,
                    work.localUpdate.not,
                    work.localUpdate.cnot,
                    work.localUpdate.toffoli,
                    work.localUpdateGates,
                ].map(formatCount);
            }),
        ),
        '',
        'Classical extraction computes the first matching active entry into a fresh output and cleans all predicate work before measuring that output. The following labelled-hash examples include their predicate computation; a different sender parser needs its actual relation circuit. Other adversary registers, circuit-generation work, full oracle routing and computational-assumption advantages remain separate.',
        '',
        table(
            [
                'Database capacity',
                'Input bits',
                'Hash bits',
                'Label bits',
                'Classical extraction gates',
                'Measured output qubits',
                'Extraction qubits',
            ],
            [
                [0n, 2n, 1n, 1n],
                [1n, 2n, 1n, 1n],
                [2n, 2n, 1n, 1n],
                [3n, 64n, 512n, 16n],
            ].map(([capacity, input, output, label]) => {
                const work = labelledHashExtractionWork(
                    capacity,
                    input,
                    output,
                    label,
                );
                return [
                    capacity,
                    input,
                    output,
                    label,
                    work.extractionGates,
                    work.measuredQubits,
                    work.extractionQubits,
                ].map(formatCount);
            }),
        ),
        '',
        'The following supplied-width prefix examples include both full-value calls, clean prefix-copy work and its extra workspace. They do not assign a maximum stream width or a complete participant/reduction total.',
        '',
        table(
            [
                'Logical accesses',
                'Input bits',
                'Maximum stream bits',
                'Full-value queries',
                'Clean prefix-copy gates per access',
                'Query gates',
                'Oracle qubit bound',
            ],
            [
                [1n, 2n, 1n],
                [1n, 2n, 2n],
                [3n, 64n, 512n],
            ].map(([queries, input, output]) => {
                const work = prefixOracleWork(queries, input, output);
                return [
                    queries,
                    input,
                    output,
                    work.fullValueQueries,
                    work.copyGates,
                    work.queryGates,
                    work.maximumQubits,
                ].map(formatCount);
            }),
        ),
        '',
        'The domain adapter below visits every eligible input-length class and output chunk for each declared query shape. Cells retain their databases across shape changes. Counts include clean length/sentinel controllers and all prefix calls. These are supplied-shape circuit bounds; extraction, other algorithm registers and classical circuit generation/dispatch remain separate. The full contribution row uses its actual maximum emitted input length for one honest query and does not bound adversarial queries.',
        '',
        table(
            [
                'Query shape',
                'Logical queries',
                'Input capacity bits',
                'Output capacity bits',
                'First chunk bits',
                'Cells',
                'Full-value calls',
                'Controller gates',
                'Total query gates',
                'Database qubits',
                'Oracle qubit bound',
            ],
            [
                {
                    name: 'Small correspondence',
                    count: 3n,
                    inputCapacity: 3n,
                    outputCapacity: 5n,
                    firstChunkBits: 2n,
                },
                {
                    name: 'Complete contribution input',
                    count: 1n,
                    inputCapacity:
                        8n *
                        compileContributionBodyCensus(completion)
                            .maximumHashInputBytes,
                    outputCapacity: 512n,
                    firstChunkBits: 512n,
                },
            ].map(({ name, firstChunkBits, ...run }) => {
                const work = oracleDomainWork([run], firstChunkBits);
                return [
                    name,
                    ...[
                        run.count,
                        run.inputCapacity,
                        run.outputCapacity,
                        firstChunkBits,
                        BigInt(work.cells.length),
                        work.fullValueQueries,
                        work.controllerGates,
                        work.queryGates,
                        work.databaseQubits,
                        work.maximumQubits,
                    ].map(formatCount),
                ];
            }),
        ),
        '',
        'A programmed-prefix read calls the complete base stream adapter twice around a clean replacement copy. The following bounded shape counts both layers and retains prior component capacity. Classical record payload excludes object metadata and dispatch work; neither is declared free.',
        '',
        table(
            [
                'Logical reads',
                'Input capacity bits',
                'Output capacity bits',
                'Replacement input bits',
                'Replacement prefix bits',
                'Full-value calls',
                'Replacement-copy gates',
                'Total query gates',
                'Oracle qubit bound',
                'Classical record payload bits',
            ],
            [[3n, 4n, 5n, 3n, 4n]].map(
                ([
                    count,
                    inputCapacity,
                    outputCapacity,
                    inputBits,
                    prefixBits,
                ]) => {
                    const work = programmedOracleDomainWork(
                        [{ count, inputCapacity, outputCapacity }],
                        2n,
                        [{ inputBits, prefixBits }],
                    );
                    return [
                        count,
                        inputCapacity,
                        outputCapacity,
                        inputBits,
                        prefixBits,
                        work.base.fullValueQueries,
                        work.copyGates,
                        work.queryGates,
                        work.maximumQubits,
                        work.classicalRecordPayloadBits,
                    ].map(formatCount);
                },
            ),
        ),
        '',
        '### Declared maximum-length oracle budget',
        '',
        'These are upper bounds for the maintained query circuits when every call is charged at its declared maximum input and output capacities. The permutation budget is the sum of those FIPS 202 reference charges, using the widest SHAKE rate conservatively. The bound sums all persistent input-class/output-chunk databases and squares each nested query multiplier in the routing term. This conditional circuit bound does not normalize arbitrary coherent-length or expected-work algorithms. Extraction, independent shadow streams and their dispatch, programming-record creation, classical circuit generation and the rest of the reduction remain separate.',
        '',
        table(
            [
                'Maximum-length permutations',
                'First output chunk bits',
                'Programmed records',
                'Controller length-bit bound',
                'Cell-bit visits bound',
                'Base query gates bound',
                'Programmed query gates bound',
            ],
            [1n, 1024n, 1n << 40n].flatMap((permutations) =>
                [0n, 1024n].map((records) => {
                    const bound = compileOraclePermutationBudget(
                        permutations,
                        512n,
                        records,
                    );
                    return [
                        permutations,
                        512n,
                        records,
                        bound.lengthBitsUpperBound,
                        bound.componentBitVisitsUpperBound,
                        bound.baseQueryGatesUpperBound,
                        bound.programmedQueryGatesUpperBound,
                    ].map(formatCount);
                }),
            ),
        ),
        '',
        '### Full-circuit query and source extraction budgets',
        '',
        'The full-circuit convention charges controlled permutation slots regardless of branch probability. Separate input and output maxima are bounded by a rectangle costing at most twice that slot budget. These examples price the complete programmed/background query circuit, every declared shadow and its selection circuit. All caller queries must enter the supplied budget; extra reduction calls, non-oracle computation and constructor work cannot be silently charged to the original experiment. The record and shadow counts below are declared examples, not a numerical registration limit.',
        '',
        table(
            [
                'Charged gates',
                'Maximum logical queries',
                'Maximum-length permutations',
                'Programmed records',
                'Shadow streams',
                'All shadow query gates bound',
            ],
            [
                [shakePermutationGateCharge, 0n, 0n],
                [1n << 40n, 10n, 20n],
                [1n << 80n, 1024n, 1024n],
            ].map(([gates, records, shadows]) => {
                const work = compileFullCircuitOracleBudget(
                    gates,
                    512n,
                    records,
                    shadows,
                );
                return [
                    gates,
                    work.maximumLogicalQueries,
                    work.maximumLengthPermutations,
                    records,
                    shadows,
                    work.shadowQueryGatesUpperBound,
                ].map(formatCount);
            }),
        ),
        '',
        'The following alternative also covers classical fixed-input XOF readers whose roots pay their complete input absorption and whose effective stream stays unchanged. Their cursor clones share a cache; separate initializations still use the same underlying XOF. An initial prefix scaled to absorption work, followed by doubling, bounds the adapter at five times the reference permutations. Each budget also has a row using the maximum emitted first-oracle replay factor derived in the proof-hash section, conditional on authenticated original-input availability. These rows replace the complete-query-only conversion above for their respective mixed interface; the conversion factors are not multiplied. All extra reduction-producer reads need their own caller budget. Reader-cache payload bounds exclude resumed hash inputs and their reconstruction/storage, handles, cursor/lookup logic, output copying, circuit construction and the oracle circuit itself. Other shared unfinished input hashes and mutable oracle epochs remain outside these conversions.',
        '',
        table(
            [
                'Charged caller gates',
                'Complete-input factor',
                'Covered prefix permutations',
                'Cached input bits bound',
                'Cached output bits bound',
                'Output growth overlap bits bound',
                'Programmed records',
                'Shadow streams',
                'All shadow query gates bound',
            ],
            [
                [shakePermutationGateCharge, 0n, 0n],
                [1n << 40n, 10n, 20n],
                [1n << 80n, 1024n, 1024n],
            ].flatMap(([gates, records, shadows]) =>
                [5n, maximumFirstOracleResume].map((factor) => {
                    const work = compileClassicalReaderOracleBudget(
                        gates,
                        512n,
                        records,
                        shadows,
                        factor,
                    );
                    return [
                        gates,
                        factor,
                        work.maximumLengthPermutations,
                        work.cacheInputBitsUpperBound,
                        work.cacheOutputBitsUpperBound,
                        work.cacheGrowthOverlapBitsUpperBound,
                        records,
                        shadows,
                        work.shadowQueryGatesUpperBound,
                    ].map(formatCount);
                }),
            ),
        ),
        '',
        'The raw registration-source slice fixes the source grammar, original owner, immutable family and salt at their actual bit positions. Its exact length is checked; the poll and the coordinate payload stay unconstrained. Current protocol credential hash calls are shorter than this source language even at its syntactic minimum. This separates raw oracle inputs, not their potentially dependent message values. Retained tags have the distinct fixed ProtocolHash prefix.',
        '',
        table(
            ['Source/credential boundary', 'Bytes'],
            [
                [
                    'Maximum current credential hash input',
                    formatCount(compileSignatureHashInputs().maximumInputBytes),
                ],
                [
                    'Syntactic minimum source input',
                    formatCount(minimumRegistrationSourceInputBytes()),
                ],
            ],
        ),
        '',
        'The following query-controller and prepared-extraction counts use the completion poll family inventory, an output prefix equal to the commitment width and a declared extraction database capacity. The separate returned-coordinate circuit checks the extracted poll, canonical centered coefficients and absence of negative zero, then copies the salt and coordinate or a zero dummy with a distinct validity bit. It includes clean compute/copy/uncompute even on missing or malformed extraction. The independent query circuit, cache indexing, circuit construction and later polynomial arithmetic remain separate costs.',
        '',
        table(
            [
                'Source family',
                'Raw input bits',
                'Hidden-slice compared bits',
                'One-slice clean routing gates',
                'Extraction component capacity',
                'Prepared selection gates per request',
                'Coordinate decoding gates per request',
                'Prepared selection and decoding gates per request',
            ],
            (() => {
                const extraction = compileRegistrationSourceExtractionWork(
                    completion.participantCount,
                    completion.optionCount,
                    1n << 40n,
                    1n,
                );
                return registrationSourceRandomness.families.map(
                    (family, index) => {
                        const inputBits = 8n * family.commitmentInputBytes;
                        const comparedBits =
                            family.commitmentMaskRawBits +
                            8n * sourceOpeningSaltBytes;
                        const routing = oracleMaskRoutingWork(inputBits, 512n, [
                            { inputLength: inputBits, comparedBits },
                        ]);
                        return [
                            family.index,
                            inputBits,
                            comparedBits,
                            routing.computeAndUncomputeGates,
                            1n << 40n,
                            extraction.families[index].preparedSelectionGates,
                            extraction.families[index].coordinateDecodingGates,
                            extraction.families[index]
                                .preparedSelectionAndDecodingGates,
                        ].map(formatCount);
                    },
                );
            })(),
        ),
        '',
        'The hidden-slice example keeps two independent shadows before one opening and one afterward. It preserves both databases and the programmed background across stages. Slice selection, nested background copies and all shadow calls are charged; record metadata, initialization and complete reduction-time conversion remain separate.',
        '',
        table(
            [
                'Background full-value calls',
                'Shadow full-value calls',
                'Slice-controller gates',
                'Replacement-copy gates',
                'Total query gates',
                'Oracle qubit bound',
                'Classical slice prefix bits',
                'Maximum programming record payload bits',
            ],
            [
                (() => {
                    const work = shadowOracleDomainWork(
                        [
                            {
                                count: 2n,
                                inputCapacity: 4n,
                                outputCapacity: 3n,
                                activeShadows: [0, 1],
                                replacements: [],
                            },
                            {
                                count: 3n,
                                inputCapacity: 4n,
                                outputCapacity: 3n,
                                activeShadows: [1],
                                replacements: [
                                    { inputBits: 4n, prefixBits: 2n },
                                ],
                            },
                        ],
                        2n,
                        [2n, 3n],
                    );
                    return [
                        work.base.fullValueQueries,
                        work.shadows.reduce(
                            (sum, value) => sum + value.fullValueQueries,
                            0n,
                        ),
                        work.routingGates,
                        work.copyGates,
                        work.queryGates,
                        work.maximumQubits,
                        work.classicalSlicePrefixBits,
                        work.maximumProgrammingRecordPayloadBits,
                    ].map(formatCount);
                })(),
            ],
        ),
        '',
    ];
};
