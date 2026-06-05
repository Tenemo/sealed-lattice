import { deriveProtocolHash } from '#packages/crypto/src/index';
import type { TranscriptCoreKernel } from '#packages/wasm/src/index';
import type {
    BgvPassiveSetupPackage,
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelExports,
} from '#packages/wasm/src/transcript-core-bridge/kernel-contracts';
import { suppliedOrFreshRandomnessHex } from '#packages/wasm/src/transcript-core-bridge/kernel-contracts';
import {
    resolveKernelBytes,
    resolveMemory,
    resolveNumberExport,
    runKernelCommand,
} from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import {
    captureRuntimeMemorySnapshot,
    type RuntimeMemorySnapshot,
} from '#tests/support/proof-benchmark-memory';

const wasmKernelUrl = new URL(
    '../../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

export const directBallotSetupSeed = 'direct-encrypted-ballot-node-wasm-seed';

export const directBallotScores = [
    10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
] as const;

export type DirectEncryptedBallotEvaluatorReplayResult = {
    readonly topCount: number;
    readonly scoreDomainMax: number;
    readonly tiePolicy: string;
    readonly workingLevel: number;
    readonly packedScoreRoot: string;
    readonly rankRoot: string;
    readonly targetProjection: string;
    readonly targetLayoutHash: string;
    readonly targetIdRoot: string;
    readonly targetOrderRoot: string;
    readonly targetCiphertextHash: string;
    readonly evaluatorReplayContextHash: string;
    readonly evaluatorReplayRecordHash: string;
    readonly targetProposal:
        | {
              readonly status: string;
              readonly requiredForFinality: string;
          }
        | {
              readonly targetProposalHash: string;
              readonly ceremonyId: string;
              readonly electionManifestHash: string;
              readonly thresholdProfileHash: string;
              readonly evaluatorReplayContextHash: string;
              readonly evaluatorReplayRecordHash: string;
              readonly encryptedBallotAggregateHash: string;
              readonly targetCiphertextHash: string;
              readonly targetLayoutHash: string;
              readonly evaluatorReplayProfileHash: string;
              readonly targetFinalityPolicyHash: string;
          };
    readonly privateCorrectnessCheck: string;
    readonly timingStatus: string;
    readonly replayTimeMilliseconds: string;
};

export type DirectEncryptedBallotResult = {
    readonly operation: 'runDirectEncryptedBallot';
    readonly profile: {
        readonly dataPrimeCount: number;
    };
    readonly ballotLayout: {
        readonly optionCount: number;
    };
    readonly input: {
        readonly ballotCount: number;
    };
    readonly encryptedBallots: {
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
        readonly responseEncoding: string;
        readonly responsePolynomialDegree: number;
        readonly sharedResponsePolynomialCount: number;
        readonly proofSizeBytes: number;
        readonly verifiedProofSizeBytes: number;
        readonly totalProofBytes: number;
        readonly proofBytesHash: string;
        readonly proofGate: string;
        readonly timingStatus: string;
        readonly challengeSoundness: string;
        readonly proofAccounting: {
            readonly challengeBits: number;
            readonly nominalChallengeBits: number;
            readonly proofModelAccepted: boolean;
            readonly weakestCheckedRelation: string;
            readonly weakestRelationEffectiveBitsPerCheck: number;
            readonly supportRelationModulusBits: number;
            readonly classicalSoundnessBitsAfterSupportUnionBound:
                | number
                | null;
            readonly maskCoefficientBits: number;
            readonly responseCoefficientBytes: number;
            readonly supportCheckCount: number;
            readonly supportMaximumDegree: number;
            readonly supportUnionLossBits: number;
            readonly targetClassicalSoundnessBits: number;
            readonly minimumIndependentRepetitionsForTarget: number | null;
            readonly minimumIndependentRepetitionsStatus: string;
            readonly estimatedIndependentRepetitionsFromWeakestRelationBeforeUnionLosses: number;
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
            readonly firstProofChunkHashes: readonly string[];
            readonly firstProofPublicTransportHash: string;
            readonly firstProofStatementHash: string;
            readonly proofProfileHash: string;
        };
        readonly proofMaskRandomness: {
            readonly source:
                | 'fresh-csprng'
                | 'development-deterministic-fixture';
            readonly ballotProofRandomnessCount: number;
            readonly randomnessBytesPerProof: number;
            readonly retention: string;
            readonly sourceStatement: string;
        };
    };
    readonly aggregation: {
        readonly ballotCount: number;
        readonly aggregateCiphertextRoot: string;
        readonly aggregateCiphertextCanonicalByteLength: number;
        readonly privateCorrectnessCheck: string;
        readonly result: string;
    };
    readonly evaluatorReplay:
        | string
        | DirectEncryptedBallotEvaluatorReplayResult
        | readonly DirectEncryptedBallotEvaluatorReplayResult[];
};

export type DirectEncryptedBallotMeasurement = {
    readonly result: DirectEncryptedBallotResult;
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

export type DirectEncryptedBallotInput = {
    readonly voterIdentity: string;
    readonly actionContextHash: string;
    readonly scores: readonly number[];
};

type DirectBallotProofMaskRandomnessInput = {
    readonly ballotProofRandomnessHexes?: readonly string[];
    readonly developmentRandomnessOverrideAcknowledged?: boolean;
};

type DirectBallotEncryptionRandomnessInput = {
    readonly ballotEncryptionSeedHexes?: readonly string[];
    readonly developmentRandomnessOverrideAcknowledged?: boolean;
};

export const createDirectBallotInputs = (
    ballotCount: number,
): readonly DirectEncryptedBallotInput[] => {
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

const defaultDirectBallotInputs = (): readonly DirectEncryptedBallotInput[] => [
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
        (_unused, randomnessIndex) => {
            const suppliedRandomnessHex =
                input.suppliedRandomnessHexes?.[randomnessIndex];
            if (
                suppliedRandomnessHex !== undefined &&
                input.developmentRandomnessOverrideAcknowledged !== true
            ) {
                throw new RangeError(
                    `Caller-supplied ${input.label} requires developmentRandomnessOverrideAcknowledged.`,
                );
            }

            const randomnessSource:
                | 'fresh-csprng'
                | 'development-deterministic-fixture' =
                suppliedRandomnessHex === undefined
                    ? 'fresh-csprng'
                    : 'development-deterministic-fixture';

            return {
                randomnessHex: suppliedOrFreshRandomnessHex(
                    suppliedRandomnessHex,
                ),
                randomnessSource,
            };
        },
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
    },
): Record<string, unknown> => {
    const ballotProofRandomnessHexes = createRandomnessHexes({
        developmentRandomnessOverrideAcknowledged:
            input.developmentRandomnessOverrideAcknowledged,
        label: 'ballotProofRandomnessHexes',
        requiredCount: input.ballotCount,
        suppliedRandomnessHexes: input.ballotProofRandomnessHexes,
    });
    const source = ballotProofRandomnessHexes.sources.find(
        (randomnessSource) => randomnessSource !== 'fresh-csprng',
    );

    return {
        source: source ?? 'fresh-csprng',
        ballotProofRandomnessHexes: ballotProofRandomnessHexes.randomnessHexes,
    };
};

export const runMeasuredInternalKernelCommand = async <Result>(
    request: Record<string, unknown>,
): Promise<{
    readonly result: Result;
    readonly memory: DirectEncryptedBallotMeasurement['memory'];
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

export const runDirectEncryptedBallot = (input: {
    readonly ballots?: readonly DirectEncryptedBallotInput[];
    readonly ballotEncryptionSeedHexes?: readonly string[];
    readonly ballotProofRandomnessHexes?: readonly string[];
    readonly developmentRandomnessOverrideAcknowledged?: boolean;
    readonly setupPackage: BgvPassiveSetupPackage;
    readonly setupSeed?: string;
    readonly topCount?: number;
    readonly topCounts?: readonly number[];
    readonly targetFinalityPolicyHash?: string;
}): Promise<DirectEncryptedBallotResult> => {
    const ballots = input.ballots ?? defaultDirectBallotInputs();

    return runInternalKernelCommand<DirectEncryptedBallotResult>({
        command: 'RunDirectEncryptedBallot',
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
        }),
        ...(input.topCount === undefined ? {} : { topCount: input.topCount }),
        ...(input.topCounts === undefined
            ? {}
            : { topCounts: input.topCounts }),
        ...(input.targetFinalityPolicyHash === undefined
            ? {}
            : { targetFinalityPolicyHash: input.targetFinalityPolicyHash }),
        ballots,
    });
};

export const runMeasuredDirectEncryptedBallot = async (input: {
    readonly ballots?: readonly DirectEncryptedBallotInput[];
    readonly ballotEncryptionSeedHexes?: readonly string[];
    readonly ballotProofRandomnessHexes?: readonly string[];
    readonly developmentRandomnessOverrideAcknowledged?: boolean;
    readonly setupPackage: BgvPassiveSetupPackage;
    readonly setupSeed?: string;
    readonly topCount?: number;
    readonly topCounts?: readonly number[];
    readonly targetFinalityPolicyHash?: string;
}): Promise<DirectEncryptedBallotMeasurement> => {
    const ballots = input.ballots ?? defaultDirectBallotInputs();

    return runMeasuredInternalKernelCommand<DirectEncryptedBallotResult>({
        command: 'RunDirectEncryptedBallot',
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
        }),
        ...(input.topCount === undefined ? {} : { topCount: input.topCount }),
        ...(input.topCounts === undefined
            ? {}
            : { topCounts: input.topCounts }),
        ...(input.targetFinalityPolicyHash === undefined
            ? {}
            : { targetFinalityPolicyHash: input.targetFinalityPolicyHash }),
        ballots,
    });
};
