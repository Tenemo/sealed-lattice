import { deriveCanonicalObjectHash } from '#packages/crypto/src/index';
import type { TranscriptCoreKernel } from '#packages/wasm/src/index';
import type {
    BgvPassiveSetupPackage,
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelExports,
} from '#packages/wasm/src/transcript-core-bridge/kernel-contracts';
import {
    resolveKernelBytes,
    resolveMemory,
    resolveNumberExport,
    runKernelCommand,
} from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';

const wasmKernelUrl = new URL(
    '../../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

export const directBallotSetupSeed = 'direct-encrypted-ballot-node-wasm-seed';

const createFreshRandomnessHex = (): string => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new Error(
            'Proof generation requires Web Crypto getRandomValues for fresh randomness.',
        );
    }
    const randomBytes = new Uint8Array(32);
    cryptoProvider.getRandomValues(randomBytes);

    return Array.from(randomBytes, (byte) =>
        byte.toString(16).padStart(2, '0'),
    ).join('');
};

const suppliedOrFreshRandomnessHex = (value: string | undefined): string =>
    value ?? createFreshRandomnessHex();

export const directBallotScores = [
    10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
] as const;

export type DirectEncryptedBallotEvaluatorReplayResult = {
    readonly topCount: number;
    readonly scoreDomainMax: number;
    readonly tiePolicy: string;
    readonly workingLevel: number;
    readonly evaluationKeyMaterialSource: string;
    readonly targetLayoutHash: string;
    readonly targetIdRoot: string;
    readonly targetOrderRoot: string;
    readonly targetCiphertextHash: string;
    readonly evaluatorReplayContextHash: string;
    readonly evaluatorReplayRecordHash: string;
    readonly targetProposal:
        | Readonly<Record<string, never>>
        | {
              readonly targetProposalHash: string;
              readonly ceremonyId: string;
              readonly electionManifestHash: string;
              readonly thresholdParametersHash: string;
              readonly evaluatorReplayContextHash: string;
              readonly evaluatorReplayRecordHash: string;
              readonly encryptedBallotAggregateHash: string;
              readonly targetCiphertextHash: string;
              readonly targetLayoutHash: string;
              readonly bgvParametersHash: string;
              readonly targetFinalityPolicyHash: string;
          };
    readonly replayTimeMilliseconds: string;
};

export type DirectEncryptedBallotResult = {
    readonly operation: 'runDirectEncryptedBallot';
    readonly parameters: {
        readonly dataPrimeCount: number;
    };
    readonly ballotLayout: {
        readonly optionCount: number;
    };
    readonly input: {
        readonly ballotCount: number;
    };
    readonly encryptedBallots: {
        readonly encryptedBallotHashes: readonly string[];
        readonly ciphertextRoots: readonly string[];
        readonly ciphertextCanonicalByteLengths: readonly number[];
    };
    readonly proofAttempt: {
        readonly proofCount: number;
        readonly rnsLimbCount: number;
        readonly responseEncoding: string;
        readonly responsePolynomialDegree: number;
        readonly proofSizeBytes: number;
        readonly totalProofBytes: number;
        readonly proofBytesHash: string;
        readonly proofGate: string;
        readonly proofTransport: {
            readonly encoding: string;
            readonly chunkSizeBytes: number;
            readonly chunksPerProof: number;
            readonly chunksForBatch: number;
            readonly transportedProofSizeBytes: number;
            readonly transportedProofBytesHash: string;
            readonly firstProofChunkMerkleRoot: string;
            readonly firstProofChunkHashes: readonly string[];
            readonly firstProofPublicTransportHash: string;
            readonly firstProofStatementHash: string;
            readonly proofParametersHash: string;
        };
    };
    readonly aggregation: {
        readonly ballotCount: number;
        readonly aggregateCiphertextRoot: string;
        readonly aggregateCiphertextCanonicalByteLength: number;
    };
    readonly evaluatorReplay:
        | string
        | DirectEncryptedBallotEvaluatorReplayResult
        | readonly DirectEncryptedBallotEvaluatorReplayResult[];
};

export const createDirectBallotSetupPackage = (
    kernel: TranscriptCoreKernel,
): BgvPassiveSetupPackage =>
    kernel.generateBgvPassiveSetup({
        ceremonyId: 'direct-encrypted-ballot-node-wasm-ceremony',
        manifestHash: deriveCanonicalObjectHash({
            objectType: 'ElectionManifestHash',
            manifest: 'direct encrypted ballot node wasm smoke',
        }),
        rosterHash: deriveCanonicalObjectHash({
            objectType: 'RosterHash',
            roster: 'direct encrypted ballot node wasm smoke',
        }),
        thresholdParametersHash: deriveCanonicalObjectHash({
            objectType: 'ThresholdParametersHash',
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
    deriveCanonicalObjectHash({
        objectType: 'ActionContextHash',
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
            actionContextHash: deriveCanonicalObjectHash({
                objectType: 'ActionContextHash',
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
}): readonly string[] => {
    if (
        input.suppliedRandomnessHexes !== undefined &&
        input.suppliedRandomnessHexes.length !== input.requiredCount
    ) {
        throw new RangeError(
            `${input.label} length must match the required count.`,
        );
    }

    return Array.from({ length: input.requiredCount }, (_unused, index) => {
        const suppliedRandomnessHex = input.suppliedRandomnessHexes?.[index];
        if (
            suppliedRandomnessHex !== undefined &&
            input.developmentRandomnessOverrideAcknowledged !== true
        ) {
            throw new RangeError(
                `Caller-supplied ${input.label} requires developmentRandomnessOverrideAcknowledged.`,
            );
        }

        return suppliedOrFreshRandomnessHex(suppliedRandomnessHex);
    });
};

const createBallotEncryptionRandomness = (
    input: DirectBallotEncryptionRandomnessInput & {
        readonly ballotCount: number;
    },
): Record<string, unknown> => {
    return {
        encryptionSeedHexes: createRandomnessHexes({
            developmentRandomnessOverrideAcknowledged:
                input.developmentRandomnessOverrideAcknowledged,
            label: 'encryptionSeedHexes',
            requiredCount: input.ballotCount,
            suppliedRandomnessHexes: input.ballotEncryptionSeedHexes,
        }),
    };
};

const createProofMaskRandomness = (
    input: DirectBallotProofMaskRandomnessInput & {
        readonly ballotCount: number;
    },
): Record<string, unknown> => {
    return {
        ballotProofRandomnessHexes: createRandomnessHexes({
            developmentRandomnessOverrideAcknowledged:
                input.developmentRandomnessOverrideAcknowledged,
            label: 'ballotProofRandomnessHexes',
            requiredCount: input.ballotCount,
            suppliedRandomnessHexes: input.ballotProofRandomnessHexes,
        }),
    };
};

export const runInternalKernelCommand = async <Result>(
    request: Record<string, unknown>,
): Promise<Result> => {
    const bytes = await resolveKernelBytes(wasmKernelUrl);
    const instantiatedSource = await WebAssembly.instantiate(bytes, {});
    const exports = instantiatedSource.instance
        .exports as TranscriptCoreKernelExports;
    const memory = resolveMemory(exports);
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

    return runKernelCommand<Result>(
        memory,
        allocate,
        deallocate,
        commandWithLength,
        request as unknown as TranscriptCoreKernelCommand,
    );
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
