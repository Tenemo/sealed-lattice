import { deriveProtocolHash } from '#packages/crypto/src/index';
import type { TranscriptCoreKernel } from '#packages/wasm/src/index';
import type {
    BgvPassiveSetupPackage,
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelExports,
} from '#packages/wasm/src/transcript-core-bridge/kernel-contracts';
import { suppliedOrFreshBridgeRandomness } from '#packages/wasm/src/transcript-core-bridge/kernel-contracts';
import {
    resolveKernelBytes,
    resolveMemory,
    resolveNumberExport,
    runKernelCommand,
} from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import {
    captureRuntimeMemorySnapshot,
    type RuntimeMemorySnapshot,
} from '#tests/support/ballot-privacy-proof-benchmark-memory';

const wasmKernelUrl = new URL(
    '../../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

export const directBallotSetupSeed = 'direct-encrypted-ballot-node-wasm-seed';

export const directBallotScores = [
    10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
] as const;

export type DirectEncryptedBallotPrototypeResult = {
    readonly operation: 'runDirectEncryptedBallotPrototype';
    readonly profile: {
        readonly dataPrimeCount: number;
    };
    readonly ballotLayout: {
        readonly optionCount: number;
    };
    readonly input: {
        readonly ballotCount: number;
    };
    readonly ballotPackages: {
        readonly ballotEncryptionRandomness: {
            readonly source:
                | 'fresh-csprng'
                | 'development-deterministic-fixture';
            readonly ballotEncryptionRandomnessCount: number;
            readonly randomnessBytesPerBallot: number;
            readonly retention: string;
            readonly sourceStatement: string;
        };
    };
    readonly proofAttempt: {
        readonly coverage: string;
        readonly proofCount: number;
        readonly rnsLimbCount: number;
        readonly proofSizeBytes: number;
        readonly verifiedProofSizeBytes: number;
        readonly totalProofBytes: number;
        readonly proofBytesHash: string;
        readonly proofGate: string;
        readonly timingStatus: string;
        readonly sharedShortResponseVectorLength: number;
        readonly duplicatedShortResponseVectorLength: number;
        readonly challengeSoundness: string;
        readonly proofAccounting: {
            readonly challengeBits: number;
            readonly classicalSoundnessBitsAfterSupportUnionBound: number;
            readonly maskCoefficientBits: number;
            readonly responseCoefficientBytes: number;
            readonly supportCheckCount: number;
            readonly supportMaximumDegree: number;
            readonly supportUnionLossBits: number;
            readonly targetClassicalSoundnessBits: number;
            readonly minimumIndependentRepetitionsForTarget: number;
            readonly estimatedRepeatedProofSizeBytes: number;
            readonly estimatedRepeatedTotalProofBytes: number;
            readonly witnessBoundBitsForMaskShiftAccounting: number;
            readonly zeroKnowledgeShiftSlackBitsAfterResponseUnionBound: number;
            readonly decision: string;
        };
        readonly proofTransport: {
            readonly encoding: string;
            readonly status: string;
            readonly retention: string;
            readonly chunkSizeBytes: number;
            readonly chunksPerProof: number;
            readonly chunksForBatch: number;
            readonly transportedProofSizeBytes: number;
            readonly transportedProofBytesHash: string;
            readonly firstProofChunkMerkleRoot: string;
        };
        readonly proofMaskRandomness: {
            readonly source:
                | 'fresh-csprng'
                | 'development-deterministic-fixture';
            readonly ballotProofRandomnessCount: number;
            readonly refreshShareProofRandomnessCount: number;
            readonly randomnessBytesPerProof: number;
            readonly retention: string;
            readonly sourceStatement: string;
        };
    };
    readonly aggregation: {
        readonly ballotCount: number;
        readonly aggregateScores: readonly number[];
        readonly plaintextOracleScores: readonly number[];
    };
    readonly evaluatorReplay:
        | string
        | {
              readonly topCount: number;
              readonly decodedTargetIds: readonly number[];
              readonly decodedTargetOrders: readonly number[];
              readonly plaintextOracleTargetIds: readonly number[];
              readonly plaintextOracleTargetOrders: readonly number[];
              readonly rankRefresh:
                  | string
                  | {
                        readonly thresholdOpening: {
                            readonly proofTransport: {
                                readonly encoding: string;
                                readonly chunkSizeBytes: number;
                                readonly chunksForOpening: number;
                            };
                            readonly shareReports: readonly {
                                readonly proofBytesHash: string;
                                readonly proofTransportedBytesHash: string;
                                readonly proofChunkCount: number;
                                readonly proofChunkMerkleRoot: string;
                            }[];
                        };
                    };
              readonly timingStatus: string;
              readonly replayTimeMilliseconds: string;
          };
};

export type DirectEncryptedBallotPrototypeMeasurement = {
    readonly result: DirectEncryptedBallotPrototypeResult;
    readonly memory: {
        readonly runtimeBefore: RuntimeMemorySnapshot;
        readonly runtimeAfter: RuntimeMemorySnapshot;
        readonly wasmLinearMemoryBytesBefore: number;
        readonly wasmLinearMemoryBytesAfter: number;
    };
};

export const createDirectBallotSetupPackage = (
    kernel: TranscriptCoreKernel,
): BgvPassiveSetupPackage =>
    kernel.generateBgvPassiveSetup({
        ceremonyId: 'direct-encrypted-ballot-node-wasm-ceremony',
        manifestHash: deriveProtocolHash('ElectionManifestHash', {
            manifest: 'direct encrypted ballot node wasm smoke',
        }),
        rosterHash: deriveProtocolHash('RosterHash', {
            roster: 'direct encrypted ballot node wasm smoke',
        }),
        thresholdProfileHash: deriveProtocolHash('ThresholdProfileHash', {
            threshold: 'direct encrypted ballot node wasm smoke',
        }),
        participants: [
            {
                trusteeIdentity: 'trustee-1',
                rosterPosition: 0,
                boardPosition: 0,
            },
            {
                trusteeIdentity: 'trustee-2',
                rosterPosition: 1,
                boardPosition: 1,
            },
            {
                trusteeIdentity: 'trustee-3',
                rosterPosition: 2,
                boardPosition: 2,
            },
        ],
        setupSeed: directBallotSetupSeed,
    });

export const directBallotActionContextHash = (): string =>
    deriveProtocolHash('ActionContextHash', {
        action: 'direct encrypted ballot node wasm smoke',
    });

export type DirectEncryptedBallotPrototypeInput = {
    readonly voterIdentity: string;
    readonly actionContextHash: string;
    readonly scores: readonly number[];
};

type DirectBallotProofMaskRandomnessInput = {
    readonly ballotProofRandomnessHexes?: readonly string[];
    readonly refreshShareProofRandomnessHexes?: readonly string[];
    readonly developmentRandomnessOverrideAcknowledged?: boolean;
};

type DirectBallotEncryptionRandomnessInput = {
    readonly ballotEncryptionSeedHexes?: readonly string[];
    readonly developmentRandomnessOverrideAcknowledged?: boolean;
};

export const createDirectBallotInputs = (
    ballotCount: number,
): readonly DirectEncryptedBallotPrototypeInput[] => {
    if (!Number.isInteger(ballotCount) || ballotCount < 1 || ballotCount > 20) {
        throw new Error('ballotCount must be an integer from 1 through 20.');
    }

    return Array.from(
        { length: ballotCount },
        (_unusedBallot, ballotIndex) => ({
            voterIdentity: `voter-node-wasm-${String(ballotIndex + 1).padStart(2, '0')}`,
            actionContextHash: deriveProtocolHash('ActionContextHash', {
                action: 'direct encrypted ballot node wasm smoke',
                ballotIndex,
            }),
            scores: directBallotScores.map((_unusedScore, optionIndex) => {
                const score = ((optionIndex + ballotIndex) % 10) + 1;

                return score;
            }),
        }),
    );
};

const defaultDirectBallotInputs =
    (): readonly DirectEncryptedBallotPrototypeInput[] => [
        {
            voterIdentity: 'voter-node-wasm-1',
            actionContextHash: directBallotActionContextHash(),
            scores: directBallotScores,
        },
    ];

const createRandomnessHexes = (input: {
    readonly developmentRandomnessOverrideAcknowledged: boolean | undefined;
    readonly label: string;
    readonly requiredCount: number;
    readonly suppliedRandomnessHexes: readonly string[] | undefined;
}): {
    readonly randomnessHexes: readonly string[];
    readonly sources: readonly (
        | 'fresh-csprng'
        | 'development-deterministic-fixture'
    )[];
} => {
    if (
        input.suppliedRandomnessHexes !== undefined &&
        input.suppliedRandomnessHexes.length !== input.requiredCount
    ) {
        throw new RangeError(
            `${input.label} length must match the required count.`,
        );
    }

    return Array.from(
        { length: input.requiredCount },
        (_unused, randomnessIndex) =>
            suppliedOrFreshBridgeRandomness(
                input.suppliedRandomnessHexes?.[randomnessIndex],
                input.developmentRandomnessOverrideAcknowledged,
            ),
    ).reduce<{
        randomnessHexes: string[];
        sources: ('fresh-csprng' | 'development-deterministic-fixture')[];
    }>(
        (accumulatedRandomness, proofRandomness) => {
            accumulatedRandomness.randomnessHexes.push(
                proofRandomness.randomnessHex,
            );
            accumulatedRandomness.sources.push(
                proofRandomness.randomnessSource,
            );

            return accumulatedRandomness;
        },
        { randomnessHexes: [], sources: [] },
    );
};

const createBallotEncryptionRandomness = (
    input: DirectBallotEncryptionRandomnessInput & {
        readonly ballotCount: number;
    },
): Record<string, unknown> => {
    const encryptionSeedHexes = createRandomnessHexes({
        developmentRandomnessOverrideAcknowledged:
            input.developmentRandomnessOverrideAcknowledged,
        label: 'encryptionSeedHexes',
        requiredCount: input.ballotCount,
        suppliedRandomnessHexes: input.ballotEncryptionSeedHexes,
    });
    const source = encryptionSeedHexes.sources.find(
        (randomnessSource) => randomnessSource !== 'fresh-csprng',
    );

    return {
        source: source ?? 'fresh-csprng',
        encryptionSeedHexes: encryptionSeedHexes.randomnessHexes,
    };
};

const createProofMaskRandomness = (
    input: DirectBallotProofMaskRandomnessInput & {
        readonly ballotCount: number;
        readonly refreshShareProofCount: number;
    },
): Record<string, unknown> => {
    const ballotProofRandomnessHexes = createRandomnessHexes({
        developmentRandomnessOverrideAcknowledged:
            input.developmentRandomnessOverrideAcknowledged,
        label: 'ballotProofRandomnessHexes',
        requiredCount: input.ballotCount,
        suppliedRandomnessHexes: input.ballotProofRandomnessHexes,
    });
    const refreshShareProofRandomnessHexes = createRandomnessHexes({
        developmentRandomnessOverrideAcknowledged:
            input.developmentRandomnessOverrideAcknowledged,
        label: 'refreshShareProofRandomnessHexes',
        requiredCount: input.refreshShareProofCount,
        suppliedRandomnessHexes: input.refreshShareProofRandomnessHexes,
    });
    const source = [
        ...ballotProofRandomnessHexes.sources,
        ...refreshShareProofRandomnessHexes.sources,
    ].find((randomnessSource) => randomnessSource !== 'fresh-csprng');

    return {
        source: source ?? 'fresh-csprng',
        ballotProofRandomnessHexes: ballotProofRandomnessHexes.randomnessHexes,
        refreshShareProofRandomnessHexes:
            refreshShareProofRandomnessHexes.randomnessHexes,
    };
};

const refreshShareProofCount = (input: {
    readonly setupPackage: BgvPassiveSetupPackage;
    readonly topCount?: number;
}): number =>
    input.topCount === undefined || input.topCount === directBallotScores.length
        ? 0
        : input.setupPackage.participants.length;

export const runMeasuredInternalKernelCommand = async <Result>(
    request: Record<string, unknown>,
): Promise<{
    readonly result: Result;
    readonly memory: DirectEncryptedBallotPrototypeMeasurement['memory'];
}> => {
    const runtimeBefore = captureRuntimeMemorySnapshot();
    const bytes = await resolveKernelBytes(wasmKernelUrl);
    const instantiatedSource = await WebAssembly.instantiate(bytes, {});
    const exports = instantiatedSource.instance
        .exports as TranscriptCoreKernelExports;
    const memory = resolveMemory(exports);
    const wasmLinearMemoryBytesBefore = memory.buffer.byteLength;
    const allocate = resolveNumberExport(
        exports,
        'sealed_lattice_allocate',
    ) as (length: number) => number;
    const deallocate = resolveNumberExport(
        exports,
        'sealed_lattice_deallocate',
    );
    const commandWithLength = resolveNumberExport(
        exports,
        'sealed_lattice_transcript_core_command_with_length',
    ) as (
        pointer: number,
        length: number,
        outputLengthPointer: number,
    ) => number;

    const result = await runKernelCommand<Result>(
        memory,
        allocate,
        deallocate,
        commandWithLength,
        request as unknown as TranscriptCoreKernelCommand,
    );
    const runtimeAfter = captureRuntimeMemorySnapshot();
    const wasmLinearMemoryBytesAfter = memory.buffer.byteLength;

    return {
        result,
        memory: {
            runtimeBefore,
            runtimeAfter,
            wasmLinearMemoryBytesBefore,
            wasmLinearMemoryBytesAfter,
        },
    };
};

export const runInternalKernelCommand = async <Result>(
    request: Record<string, unknown>,
): Promise<Result> => {
    const measured = await runMeasuredInternalKernelCommand<Result>(request);

    return measured.result;
};

export const runDirectEncryptedBallotPrototype = (input: {
    readonly ballots?: readonly DirectEncryptedBallotPrototypeInput[];
    readonly ballotEncryptionSeedHexes?: readonly string[];
    readonly ballotProofRandomnessHexes?: readonly string[];
    readonly developmentRandomnessOverrideAcknowledged?: boolean;
    readonly refreshShareProofRandomnessHexes?: readonly string[];
    readonly setupPackage: BgvPassiveSetupPackage;
    readonly setupSeed?: string;
    readonly topCount?: number;
}): Promise<DirectEncryptedBallotPrototypeResult> => {
    const ballots = input.ballots ?? defaultDirectBallotInputs();

    return runInternalKernelCommand<DirectEncryptedBallotPrototypeResult>({
        command: 'RunDirectEncryptedBallotPrototype',
        setupPackage: input.setupPackage,
        setupPrivateWitness: {
            setupSeed: input.setupSeed ?? directBallotSetupSeed,
        },
        ballotEncryptionRandomness: createBallotEncryptionRandomness({
            ballotCount: ballots.length,
            ballotEncryptionSeedHexes: input.ballotEncryptionSeedHexes,
            developmentRandomnessOverrideAcknowledged:
                input.developmentRandomnessOverrideAcknowledged,
        }),
        proofMaskRandomness: createProofMaskRandomness({
            ballotCount: ballots.length,
            ballotProofRandomnessHexes: input.ballotProofRandomnessHexes,
            developmentRandomnessOverrideAcknowledged:
                input.developmentRandomnessOverrideAcknowledged,
            refreshShareProofCount: refreshShareProofCount(input),
            refreshShareProofRandomnessHexes:
                input.refreshShareProofRandomnessHexes,
        }),
        ...(input.topCount === undefined ? {} : { topCount: input.topCount }),
        ballots,
    });
};

export const runMeasuredDirectEncryptedBallotPrototype = async (input: {
    readonly ballots?: readonly DirectEncryptedBallotPrototypeInput[];
    readonly ballotEncryptionSeedHexes?: readonly string[];
    readonly ballotProofRandomnessHexes?: readonly string[];
    readonly developmentRandomnessOverrideAcknowledged?: boolean;
    readonly refreshShareProofRandomnessHexes?: readonly string[];
    readonly setupPackage: BgvPassiveSetupPackage;
    readonly setupSeed?: string;
    readonly topCount?: number;
}): Promise<DirectEncryptedBallotPrototypeMeasurement> => {
    const ballots = input.ballots ?? defaultDirectBallotInputs();

    return runMeasuredInternalKernelCommand<DirectEncryptedBallotPrototypeResult>(
        {
            command: 'RunDirectEncryptedBallotPrototype',
            setupPackage: input.setupPackage,
            setupPrivateWitness: {
                setupSeed: input.setupSeed ?? directBallotSetupSeed,
            },
            ballotEncryptionRandomness: createBallotEncryptionRandomness({
                ballotCount: ballots.length,
                ballotEncryptionSeedHexes: input.ballotEncryptionSeedHexes,
                developmentRandomnessOverrideAcknowledged:
                    input.developmentRandomnessOverrideAcknowledged,
            }),
            proofMaskRandomness: createProofMaskRandomness({
                ballotCount: ballots.length,
                ballotProofRandomnessHexes: input.ballotProofRandomnessHexes,
                developmentRandomnessOverrideAcknowledged:
                    input.developmentRandomnessOverrideAcknowledged,
                refreshShareProofCount: refreshShareProofCount(input),
                refreshShareProofRandomnessHexes:
                    input.refreshShareProofRandomnessHexes,
            }),
            ...(input.topCount === undefined
                ? {}
                : { topCount: input.topCount }),
            ballots,
        },
    );
};
