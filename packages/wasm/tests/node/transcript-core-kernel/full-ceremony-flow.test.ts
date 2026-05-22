import { spawn } from 'node:child_process';
import { availableParallelism } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import type {
    ActionContext,
    CastReceipt,
    ClaimBearingBallotPackage,
    CloseRecord,
    ElectionManifest,
    FrozenRosterProfile,
    InclusionProof,
    PollSpec,
    ProtocolDigest,
    RosterExternalAcceptance,
    RosterManifestTranscriptInput,
    SignedBoardHead,
    TargetFinalityRecord,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '../../../src/index';

import {
    generateFullCeremonyVoterArtifact,
    type FullCeremonyVoterWorkerInput,
    type FullCeremonyVoterWorkerOutput,
} from './full-ceremony-voter-worker.js';

import { deriveProtocolDigest } from '#packages/crypto/src/index';
import {
    buildAggregateDerivationProofInput,
    buildAggregateDerivationStatement,
    createAggregateDerivationComponent,
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
    sumAggregateDerivationWitnesses,
} from '#packages/protocol/src/ballot-privacy/index';
import {
    deriveCastReceiptDigest,
    deriveCloseRecordDigest,
    derivePostVotingClosedContextDigest,
    verifyCastReceiptShell,
} from '#packages/protocol/src/closing/index';
import {
    deriveTargetFinalityCheckpointDigest,
    deriveTargetFinalityRecordDigest,
    deriveTargetProposalDigest,
    deriveWitnessCheckpointDigest,
    verifyTargetFinality,
} from '#packages/protocol/src/finality/index';
import {
    derivePollSpecDigest,
    validatePollSpec,
} from '#packages/protocol/src/lifecycle/poll-spec';
import {
    deriveFrozenRosterProfile,
    deriveThresholdProfile,
} from '#packages/protocol/src/lifecycle/thresholds';
import { derivePlaintextTopKOracle } from '#packages/protocol/src/plaintext-oracle/index';
import {
    deriveActionContextDigest,
    isActionCurrentForRecoveryEpoch,
} from '#packages/protocol/src/recovery/index';
import {
    deriveElectionManifestDigest,
    deriveRosterDigest,
    deriveRosterExternalAcceptanceDigest,
} from '#packages/protocol/src/roster/digests';
import {
    verifyRosterExternalAcceptance,
    verifyRosterManifestTranscript,
} from '#packages/protocol/src/roster/index';
import {
    boardPolicyDigest,
    ceremonyId,
    createBoardEvidence,
    createBoardHead,
    createBoardHeadWithObjects,
    createReceiverKeyRegistration,
    createRegistrationEntry,
    createSignature,
    createTrusteeSetupEntry,
    getParticipantSigningPublicKeyDigest,
    getWitnessKeyFixture,
    manifestOpaqueBindings,
    manifestPolicyDigests,
    targetFinalityPolicy,
    targetFinalityPolicyDigest,
    witnessIdentities,
    witnessPolicy,
    witnessPolicyDigest,
    witnessPublicKeyDigests,
} from '#packages/protocol/tests/node/election-foundation-test-helpers';
import {
    createJsonCheckpointStore,
    shouldResumeFromTestCheckpoints,
} from '#tests/support/node-test-checkpoints';

type FullCeremonyRoster = {
    readonly boardEvidence: RosterManifestTranscriptInput['boardEvidence'];
    readonly freezeHead: SignedBoardHead;
    readonly frozenRosterProfile: FrozenRosterProfile;
    readonly manifestHead: SignedBoardHead;
    readonly participantIdentities: readonly string[];
    readonly pollSpec: PollSpec;
    readonly rosterTranscript: RosterManifestTranscriptInput;
};

type VoterPlan = {
    readonly actionSequence: number;
    readonly normalizedScores: readonly number[];
    readonly voterIdentity: string;
    readonly voterRosterPosition: number;
};

type VoterCeremonyInput = {
    readonly actionContext: ActionContext;
    readonly rosterAcceptance: RosterExternalAcceptance;
    readonly workerInput: FullCeremonyVoterWorkerInput;
};

type CastArtifact = {
    readonly inclusionProof: InclusionProof;
    readonly publicArtifact: FullCeremonyVoterWorkerOutput['publicArtifact'];
    readonly receipt: CastReceipt;
};

type CountedBallotSelection = {
    readonly ballotSetDigest: ProtocolDigest;
    readonly countedArtifacts: readonly FullCeremonyVoterWorkerOutput[];
    readonly lateReceiptDigests: readonly ProtocolDigest[];
};

const requireValue = <Value>(
    value: Value | undefined,
    message: string,
): Value => {
    if (value === undefined) {
        throw new Error(message);
    }

    return value;
};

const digest = (label: string, value: unknown = {}): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        label,
        purpose: 'full-ceremony-flow',
        value,
    });

const deterministicRandomnessHex = (label: string): string =>
    digest('deterministic-randomness', { label }).slice(0, 64);

const createFullCeremonyPollSpec = (): PollSpec => {
    const validation = validatePollSpec({
        duplicateBallotPolicy: 'LastValidBeforeVotingClosedCounts',
        maxRosterSize: 50,
        minRosterSize: 10,
        options: Array.from(
            { length: 20 },
            (_unusedValue, optionIndex) => `Option ${optionIndex + 1}`,
        ),
        pollId: 'full-implemented-ceremony-flow',
        question: 'Rank the implementation options',
        rosterPolicy: 'OpenLinkPublicRoster',
        scoreDomain: { max: 10, min: 1, skippedOptionScore: 1 },
        smallRosterPolicy: 'ForbidMicroRoster',
        thresholdProfileFamily: 'BalancedDefault',
        tiePolicy: 'HigherScoreThenLowerOptionIndex',
        topOptionCount: 3,
    });
    if (!validation.ok) {
        throw new Error('Full ceremony poll specification should be valid.');
    }

    return validation.normalized;
};

const createElectionManifest = (input: {
    readonly frozenRosterProfile: FrozenRosterProfile;
    readonly organizerIdentity: string;
    readonly organizerPublicKeyDigest: ProtocolDigest;
    readonly pollSpec: PollSpec;
    readonly rosterDigest: ProtocolDigest;
}): ElectionManifest => {
    const manifestPayload = {
        objectType: 'ElectionManifest',
        objectVersion: 1,
        boardPosition: 0,
        boardSequence: 3,
        ceremonyId,
        manifestOpaqueBindings,
        manifestPolicyDigests,
        pollSpecDigest: derivePollSpecDigest(input.pollSpec),
        rosterDigest: input.rosterDigest,
        thresholdProfileDigest:
            input.frozenRosterProfile.thresholdProfileDigest,
    } satisfies Omit<ElectionManifest, 'electionManifestDigest' | 'signature'>;
    const electionManifestDigest =
        deriveElectionManifestDigest(manifestPayload);

    return {
        ...manifestPayload,
        electionManifestDigest,
        signature: createSignature(
            'ElectionManifest',
            'Organizer',
            input.organizerIdentity,
            input.organizerPublicKeyDigest,
            electionManifestDigest,
        ),
    };
};

const inclusionProofForObject = (
    inclusionProofs: readonly InclusionProof[],
    objectDigest: ProtocolDigest,
): InclusionProof =>
    requireValue(
        inclusionProofs.find(
            (inclusionProof) =>
                inclusionProof.includedObjectDigest === objectDigest,
        ),
        `Missing inclusion proof for ${objectDigest}.`,
    );

const createFullCeremonyRoster = (): FullCeremonyRoster => {
    const participantIdentities = Array.from(
        { length: 20 },
        (_unusedValue, participantIndex) => `receiver-${participantIndex + 1}`,
    );
    const registrationEntries = participantIdentities.map(
        (participantIdentity, participantIndex) =>
            createRegistrationEntry(participantIdentity, 1, participantIndex),
    );
    const receiverKeyRegistrations = participantIdentities.map(
        (participantIdentity, participantIndex) =>
            createReceiverKeyRegistration(
                participantIdentity,
                1,
                participantIdentities.length + participantIndex,
            ),
    );
    const trusteeSetupEntries = participantIdentities.map(
        (participantIdentity, participantIndex) =>
            createTrusteeSetupEntry(
                participantIdentity,
                1,
                participantIdentities.length * 2 + participantIndex,
            ),
    );
    const setupObjects = [
        ...registrationEntries.map((entry) => ({
            boardPosition: entry.boardPosition,
            objectDigest: entry.registrationEntryDigest,
            objectType: 'RegistrationEntry' as const,
        })),
        ...receiverKeyRegistrations.map((entry) => ({
            boardPosition: entry.boardPosition,
            objectDigest: entry.receiverKeyRegistrationDigest,
            objectType: 'ReceiverKeyRegistration' as const,
        })),
        ...trusteeSetupEntries.map((entry) => ({
            boardPosition: entry.boardPosition,
            objectDigest: entry.trusteeSetupEntryDigest,
            objectType: 'TrusteeSetupEntry' as const,
        })),
    ];
    const genesisHead = createBoardHead(0, null, 'full-ceremony-flow');
    const { head: setupHead, inclusionProofs: setupInclusionProofs } =
        createBoardHeadWithObjects(
            1,
            genesisHead.headDigest,
            setupObjects,
            'full-ceremony-flow',
        );
    const freezeHead = createBoardHead(
        2,
        setupHead.headDigest,
        'full-ceremony-flow',
    );
    const pollSpec = createFullCeremonyPollSpec();
    const rosterDigest = deriveRosterDigest(registrationEntries);
    const frozenRosterProfile = deriveFrozenRosterProfile({
        pollSpec,
        rosterDigest,
        rosterSize: participantIdentities.length,
    });
    const organizerIdentity = participantIdentities[0];
    const organizerPublicKeyDigest =
        getParticipantSigningPublicKeyDigest(organizerIdentity);
    const electionManifest = createElectionManifest({
        frozenRosterProfile,
        organizerIdentity,
        organizerPublicKeyDigest,
        pollSpec,
        rosterDigest,
    });
    const { head: manifestHead, inclusionProofs: manifestInclusionProofs } =
        createBoardHeadWithObjects(
            3,
            freezeHead.headDigest,
            [
                {
                    boardPosition: electionManifest.boardPosition,
                    objectDigest: electionManifest.electionManifestDigest,
                    objectType: 'ElectionManifest',
                },
            ],
            'full-ceremony-flow',
        );
    const boardEvidence = createBoardEvidence([
        genesisHead,
        setupHead,
        freezeHead,
        manifestHead,
    ]);
    const rosterTranscript: RosterManifestTranscriptInput = {
        boardEvidence,
        ceremonyId,
        electionManifest,
        frozenRosterProfile,
        manifestInclusionProof: manifestInclusionProofs[0],
        organizerIdentity,
        organizerPublicKeyDigest,
        pollSpec,
        receiverKeyRegistrationInclusionProofs: receiverKeyRegistrations.map(
            (entry) =>
                inclusionProofForObject(
                    setupInclusionProofs,
                    entry.receiverKeyRegistrationDigest,
                ),
        ),
        receiverKeyRegistrations,
        registrationEntries,
        registrationInclusionProofs: registrationEntries.map((entry) =>
            inclusionProofForObject(
                setupInclusionProofs,
                entry.registrationEntryDigest,
            ),
        ),
        rosterFreezeBoardSequence: freezeHead.boardSequence,
        trusteeSetupEntries,
        trusteeSetupInclusionProofs: trusteeSetupEntries.map((entry) =>
            inclusionProofForObject(
                setupInclusionProofs,
                entry.trusteeSetupEntryDigest,
            ),
        ),
    };

    return {
        boardEvidence,
        freezeHead,
        frozenRosterProfile,
        manifestHead,
        participantIdentities,
        pollSpec,
        rosterTranscript,
    };
};

const createRosterExternalAcceptance = (input: {
    readonly acceptedBoardHeadDigest: ProtocolDigest;
    readonly electionManifestDigest: ProtocolDigest;
    readonly participantIdentity: string;
    readonly rosterDigest: ProtocolDigest;
}): RosterExternalAcceptance => {
    const acceptancePayload = {
        objectType: 'RosterExternalAcceptance',
        objectVersion: 1,
        acceptedBoardHeadDigest: input.acceptedBoardHeadDigest,
        ceremonyId,
        electionManifestDigest: input.electionManifestDigest,
        participantIdentity: input.participantIdentity,
        rosterDigest: input.rosterDigest,
        warningTextVersion: 'open-link-public-roster-warning-v1',
    } satisfies Omit<
        RosterExternalAcceptance,
        'rosterExternalAcceptanceDigest' | 'signature'
    >;
    const rosterExternalAcceptanceDigest =
        deriveRosterExternalAcceptanceDigest(acceptancePayload);

    return {
        ...acceptancePayload,
        rosterExternalAcceptanceDigest,
        signature: createSignature(
            'RosterExternalAcceptance',
            'Participant',
            input.participantIdentity,
            getParticipantSigningPublicKeyDigest(input.participantIdentity),
            rosterExternalAcceptanceDigest,
            {
                boardHeadDigest: input.acceptedBoardHeadDigest,
                manifestDigest: input.electionManifestDigest,
            },
        ),
    };
};

const createActionContext = (input: {
    readonly actionSequence: number;
    readonly boardHead: SignedBoardHead;
    readonly contextDigest: ProtocolDigest;
    readonly electionManifestDigest: ProtocolDigest;
    readonly rosterExternalAcceptanceDigest: ProtocolDigest;
    readonly signerIdentity: string;
}): ActionContext => {
    const actionContextPayload = {
        acceptedRecoveryEpochUpdateDigest: null,
        actionSequence: input.actionSequence,
        boardHeadDigest: input.boardHead.headDigest,
        boardSequence: input.boardHead.boardSequence,
        ceremonyId,
        contextDigest: input.contextDigest,
        deviceEpoch: 0,
        electionManifestDigest: input.electionManifestDigest,
        recoveryEpoch: 0,
        recoveryPolicyDigest: manifestPolicyDigests.recoveryPolicyDigest,
        rosterExternalAcceptanceDigest: input.rosterExternalAcceptanceDigest,
        signerIdentity: input.signerIdentity,
    } satisfies Omit<ActionContext, 'actionContextDigest'>;

    return {
        ...actionContextPayload,
        actionContextDigest: deriveActionContextDigest(actionContextPayload),
    };
};

const buildVoterCeremonyInput = (input: {
    readonly ceremonyPublicInput: FullCeremonyVoterWorkerInput['ceremony'];
    readonly manifestHead: SignedBoardHead;
    readonly plan: VoterPlan;
    readonly rosterTranscript: RosterManifestTranscriptInput;
}): VoterCeremonyInput => {
    const rosterAcceptance = createRosterExternalAcceptance({
        acceptedBoardHeadDigest: input.manifestHead.headDigest,
        electionManifestDigest:
            input.rosterTranscript.electionManifest.electionManifestDigest,
        participantIdentity: input.plan.voterIdentity,
        rosterDigest: input.rosterTranscript.electionManifest.rosterDigest,
    });
    const actionContext = createActionContext({
        actionSequence: input.plan.actionSequence,
        boardHead: input.manifestHead,
        contextDigest: digest('voter-action-context', {
            actionSequence: input.plan.actionSequence,
            voterIdentity: input.plan.voterIdentity,
        }),
        electionManifestDigest:
            input.rosterTranscript.electionManifest.electionManifestDigest,
        rosterExternalAcceptanceDigest:
            rosterAcceptance.rosterExternalAcceptanceDigest,
        signerIdentity: input.plan.voterIdentity,
    });

    return {
        actionContext,
        rosterAcceptance,
        workerInput: {
            ceremony: input.ceremonyPublicInput,
            contributorRosterPosition: 1,
            voter: {
                actionContextDigest: actionContext.actionContextDigest,
                normalizedScores: input.plan.normalizedScores,
                payloadContextDigest: digest('payload-context', {
                    actionSequence: input.plan.actionSequence,
                    voterIdentity: input.plan.voterIdentity,
                }),
                randomnessSeedLabel: [
                    'full-ceremony-flow',
                    input.plan.voterIdentity,
                    input.plan.actionSequence,
                ].join(':'),
                rosterExternalAcceptanceDigest:
                    rosterAcceptance.rosterExternalAcceptanceDigest,
                voterIdentity: input.plan.voterIdentity,
                voterIdentityDigest: digest('voter-identity', {
                    voterIdentity: input.plan.voterIdentity,
                }),
                voterRosterPosition: input.plan.voterRosterPosition,
                voterSigningKeyDigest: getParticipantSigningPublicKeyDigest(
                    input.plan.voterIdentity,
                ),
            },
        },
    };
};

const recordValue = (value: unknown): Record<string, unknown> | undefined =>
    typeof value === 'object' && value !== null && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : undefined;

const checkpointBindingDigest = (
    workerInput: FullCeremonyVoterWorkerInput,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'full-ceremony-flow-voter-checkpoint-binding',
        workerInput,
    });

const generateVoterArtifactWithCheckpoint = async (input: {
    readonly checkpointStore: ReturnType<typeof createJsonCheckpointStore>;
    readonly generateOutput: (
        workerInput: FullCeremonyVoterWorkerInput,
    ) => Promise<FullCeremonyVoterWorkerOutput>;
    readonly workerInput: FullCeremonyVoterWorkerInput;
}): Promise<FullCeremonyVoterWorkerOutput> => {
    const randomnessSeedParts =
        input.workerInput.voter.randomnessSeedLabel.split(':');
    const actionSequenceLabel = requireValue(
        randomnessSeedParts[randomnessSeedParts.length - 1],
        'Voter randomness seed label should include an action sequence.',
    );
    const checkpointName = [
        'full-ceremony-flow-voter',
        input.workerInput.voter.voterIdentity,
        `action-${actionSequenceLabel}`,
    ]
        .join('-')
        .replace(/[^a-z0-9-]/gu, '-');
    const bindingDigest = checkpointBindingDigest(input.workerInput);
    if (shouldResumeFromTestCheckpoints()) {
        const checkpoint = recordValue(
            input.checkpointStore.read(checkpointName),
        );
        if (
            checkpoint?.schemaVersion === 1 &&
            checkpoint.checkpointName === checkpointName &&
            checkpoint.checkpointBindingDigest === bindingDigest
        ) {
            return checkpoint.output as FullCeremonyVoterWorkerOutput;
        }
    }

    const output = await input.generateOutput(input.workerInput);
    input.checkpointStore.write(checkpointName, {
        checkpointBindingDigest: bindingDigest,
        checkpointName,
        output,
        schemaVersion: 1,
    });

    return output;
};

const parseCeremonyWorkerCount = (taskCount: number): number => {
    const configuredWorkerCount = process.env.SEALED_LATTICE_CEREMONY_WORKERS;
    if (configuredWorkerCount === undefined) {
        return 1;
    }
    const requestedWorkerCount = Number(configuredWorkerCount);
    if (
        !Number.isSafeInteger(requestedWorkerCount) ||
        requestedWorkerCount < 1
    ) {
        throw new RangeError(
            'SEALED_LATTICE_CEREMONY_WORKERS must be a positive integer.',
        );
    }

    const localParallelism = Math.max(1, availableParallelism() - 1);

    return Math.min(taskCount, requestedWorkerCount, localParallelism);
};

const runVoterWorkerProcess = async (
    workerInput: FullCeremonyVoterWorkerInput,
): Promise<FullCeremonyVoterWorkerOutput> => {
    const workerFilePath = fileURLToPath(
        new URL('./full-ceremony-voter-worker.ts', import.meta.url),
    );
    const tsxCliPath = path.resolve(
        process.cwd(),
        'node_modules',
        'tsx',
        'dist',
        'cli.mjs',
    );
    const rootTsconfigPath = path.resolve(process.cwd(), 'tsconfig.base.json');

    return await new Promise((resolve, reject) => {
        const workerProcess = spawn(
            process.execPath,
            [tsxCliPath, '--tsconfig', rootTsconfigPath, workerFilePath],
            {
                cwd: process.cwd(),
                env: process.env,
                stdio: ['pipe', 'pipe', 'pipe'],
            },
        );
        let standardOutput = '';
        let standardError = '';
        workerProcess.stdout.setEncoding('utf8');
        workerProcess.stderr.setEncoding('utf8');
        workerProcess.stdout.on('data', (chunk: string) => {
            standardOutput += chunk;
        });
        workerProcess.stderr.on('data', (chunk: string) => {
            standardError += chunk;
        });
        workerProcess.on('error', reject);
        workerProcess.on('close', (exitCode) => {
            if (exitCode !== 0) {
                reject(
                    new Error(
                        `Voter worker failed with exit code ${String(
                            exitCode,
                        )}: ${standardError}`,
                    ),
                );
                return;
            }
            resolve(
                JSON.parse(standardOutput) as FullCeremonyVoterWorkerOutput,
            );
        });
        workerProcess.stdin.end(JSON.stringify(workerInput));
    });
};

const generateVoterArtifacts = async (input: {
    readonly checkpointStore: ReturnType<typeof createJsonCheckpointStore>;
    readonly workerInputs: readonly FullCeremonyVoterWorkerInput[];
}): Promise<readonly FullCeremonyVoterWorkerOutput[]> => {
    const workerCount = parseCeremonyWorkerCount(input.workerInputs.length);
    if (workerCount === 1) {
        const outputs: FullCeremonyVoterWorkerOutput[] = [];
        for (const workerInput of input.workerInputs) {
            outputs.push(
                await generateVoterArtifactWithCheckpoint({
                    checkpointStore: input.checkpointStore,
                    generateOutput: generateFullCeremonyVoterArtifact,
                    workerInput,
                }),
            );
        }

        return outputs;
    }

    const outputs: FullCeremonyVoterWorkerOutput[] = [];
    let nextWorkerInputIndex = 0;
    const runWorkerLoop = async (): Promise<void> => {
        while (nextWorkerInputIndex < input.workerInputs.length) {
            const workerInputIndex = nextWorkerInputIndex;
            nextWorkerInputIndex += 1;
            const workerInput = input.workerInputs[workerInputIndex];
            outputs[workerInputIndex] =
                await generateVoterArtifactWithCheckpoint({
                    checkpointStore: input.checkpointStore,
                    generateOutput: runVoterWorkerProcess,
                    workerInput,
                });
        }
    };
    await Promise.all(
        Array.from({ length: workerCount }, () => runWorkerLoop()),
    );

    return outputs.map((output) =>
        requireValue(output, 'Voter worker did not return an output.'),
    );
};

const createCastReceiptPayload = (input: {
    readonly actionContextDigest: ProtocolDigest;
    readonly ballotPackageDigest: ProtocolDigest;
    readonly boardPosition: number;
    readonly boardSequence: number;
    readonly electionManifestDigest: ProtocolDigest;
    readonly voterIdentity: string;
}): Omit<CastReceipt, 'castReceiptDigest' | 'signature'> => ({
    objectType: 'CastReceipt',
    objectVersion: 1,
    ballotPackageDigest: input.ballotPackageDigest,
    boardPosition: input.boardPosition,
    boardSequence: input.boardSequence,
    ceremonyId,
    contextDigest: input.actionContextDigest,
    deviceEpoch: 0,
    electionManifestDigest: input.electionManifestDigest,
    recoveryEpoch: 0,
    voterIdentity: input.voterIdentity,
});

const signCastReceipt = (input: {
    readonly boardHeadDigest: ProtocolDigest;
    readonly payload: Omit<CastReceipt, 'castReceiptDigest' | 'signature'>;
}): CastReceipt => {
    const castReceiptDigest = deriveCastReceiptDigest(input.payload);

    return {
        ...input.payload,
        castReceiptDigest,
        signature: createSignature(
            'CastReceipt',
            'Voter',
            input.payload.voterIdentity,
            getParticipantSigningPublicKeyDigest(input.payload.voterIdentity),
            castReceiptDigest,
            {
                boardHeadDigest: input.boardHeadDigest,
                contextDigest: input.payload.contextDigest,
                manifestDigest: input.payload.electionManifestDigest,
            },
        ),
    };
};

const createCloseRecord = (input: {
    readonly boardHeadDigest: ProtocolDigest;
    readonly boardPosition: number;
    readonly boardSequence: number;
    readonly closedBoardHeadDigest: ProtocolDigest;
    readonly electionManifestDigest: ProtocolDigest;
    readonly organizerIdentity: string;
    readonly postVotingClosedContextDigest: ProtocolDigest;
}): CloseRecord => {
    const closeRecordPayload = {
        objectType: 'CloseRecord',
        objectVersion: 1,
        boardPosition: input.boardPosition,
        boardSequence: input.boardSequence,
        ceremonyId,
        closeKind: 'VotingClosed',
        closedBoardHeadDigest: input.closedBoardHeadDigest,
        electionManifestDigest: input.electionManifestDigest,
        organizerIdentity: input.organizerIdentity,
    } satisfies Omit<
        CloseRecord,
        'closeRecordDigest' | 'postVotingClosedContextDigest' | 'signature'
    >;
    const closeRecordDigest = deriveCloseRecordDigest(closeRecordPayload);

    return {
        ...closeRecordPayload,
        closeRecordDigest,
        postVotingClosedContextDigest: input.postVotingClosedContextDigest,
        signature: createSignature(
            'CloseRecord',
            'Organizer',
            input.organizerIdentity,
            getParticipantSigningPublicKeyDigest(input.organizerIdentity),
            closeRecordDigest,
            {
                boardHeadDigest: input.boardHeadDigest,
                contextDigest: input.postVotingClosedContextDigest,
                manifestDigest: input.electionManifestDigest,
            },
        ),
    };
};

const createCastBoard = (input: {
    readonly actionContexts: readonly ActionContext[];
    readonly artifacts: readonly FullCeremonyVoterWorkerOutput[];
    readonly electionManifestDigest: ProtocolDigest;
    readonly previousHeadDigest: ProtocolDigest;
}): {
    readonly castArtifacts: readonly CastArtifact[];
    readonly castHead: SignedBoardHead;
} => {
    const receiptPayloads = input.artifacts.map((artifact, artifactIndex) =>
        createCastReceiptPayload({
            actionContextDigest: requireValue(
                input.actionContexts[artifactIndex],
                'Missing voter action context.',
            ).actionContextDigest,
            ballotPackageDigest: artifact.publicArtifact.ballotPackageDigest,
            boardPosition: artifactIndex,
            boardSequence: 4,
            electionManifestDigest: input.electionManifestDigest,
            voterIdentity: artifact.publicArtifact.voterIdentity,
        }),
    );
    const receiptDigests = receiptPayloads.map((receiptPayload) =>
        deriveCastReceiptDigest(receiptPayload),
    );
    const { head: castHead, inclusionProofs } = createBoardHeadWithObjects(
        4,
        input.previousHeadDigest,
        receiptDigests.map((receiptDigest, receiptIndex) => ({
            boardPosition: receiptIndex,
            objectDigest: receiptDigest,
            objectType: 'CastReceipt',
        })),
        'full-ceremony-flow',
    );
    const castArtifacts = receiptPayloads.map(
        (receiptPayload, receiptIndex) => ({
            inclusionProof: inclusionProofs[receiptIndex],
            publicArtifact: input.artifacts[receiptIndex].publicArtifact,
            receipt: signCastReceipt({
                boardHeadDigest: castHead.headDigest,
                payload: receiptPayload,
            }),
        }),
    );

    return { castArtifacts, castHead };
};

const createTargetFinalityRecordForOracle = (input: {
    readonly finalizedHead: SignedBoardHead;
    readonly manifestDigest: ProtocolDigest;
    readonly topKEvaluationInclusionProof: InclusionProof;
    readonly topKEvaluationRecordDigest: ProtocolDigest;
}): TargetFinalityRecord => {
    const proposalPayload = {
        ceremonyId,
        electionManifestDigest: input.manifestDigest,
        evaluationContextDigest: digest('plaintext-oracle-evaluation-context'),
        topKEvaluationRecordDigest: input.topKEvaluationRecordDigest,
        topKCiphertextDigest: deriveProtocolDigest('CiphertextRoot', {
            purpose: 'full-ceremony-flow-shell-top-k-ciphertext',
        }),
        publicSlotMaskDigest: deriveProtocolDigest('PublicSlotMaskDigest', {
            purpose: 'full-ceremony-flow-shell-public-slot-mask',
        }),
        targetCiphertextDigest: deriveProtocolDigest('CiphertextRoot', {
            purpose: 'full-ceremony-flow-shell-target-ciphertext',
        }),
        targetLayoutDigest: deriveProtocolDigest('TargetLayoutDigest', {
            layout: 'WinnerRankTopK-v1',
        }),
        evaluationProofProfileDigest:
            manifestOpaqueBindings.evaluationProofProfileDigest,
        targetFinalityPolicyDigest,
    };
    const targetProposalDigest = deriveTargetProposalDigest(proposalPayload);
    const checkpointPayload = {
        ...proposalPayload,
        objectType: 'TargetFinalityCheckpoint',
        objectVersion: 1,
        boardPolicyDigest,
        finalizedBoardHeadDigest: input.finalizedHead.headDigest,
        targetProposalDigest,
        witnessPolicyDigest,
    } as const;
    const targetFinalityCheckpointDigest =
        deriveTargetFinalityCheckpointDigest(checkpointPayload);
    const targetFinalityCheckpoint = {
        ...checkpointPayload,
        targetFinalityCheckpointDigest,
    };
    const witnessCheckpoints = witnessIdentities
        .slice(0, 5)
        .map((witnessIdentity) => {
            const witnessCheckpointPayload = {
                objectType: 'WitnessCheckpoint',
                objectVersion: 1,
                ceremonyId,
                targetFinalityCheckpointDigest,
                targetFinalityPolicyDigest,
                targetFinalityScope: 'target',
                targetProposalDigest,
                witnessIdentity,
                witnessPolicyDigest,
            } as const;
            const checkpointDigest = deriveWitnessCheckpointDigest(
                witnessCheckpointPayload,
            );

            return {
                ...witnessCheckpointPayload,
                checkpointDigest,
                signature: createSignature(
                    'WitnessCheckpoint',
                    'Witness',
                    witnessIdentity,
                    getWitnessKeyFixture(witnessIdentity).publicKeyDigest,
                    checkpointDigest,
                    {
                        boardHeadDigest: input.finalizedHead.headDigest,
                        manifestDigest: input.manifestDigest,
                    },
                ),
            };
        });
    const finalityPayload = {
        objectType: 'TargetFinalityRecord',
        objectVersion: 1,
        ceremonyId,
        inclusionProof: input.topKEvaluationInclusionProof,
        targetFinalityCheckpoint,
        targetFinalityPolicyDigest,
        targetFinalityScope: 'target',
        targetProposalDigest,
        witnessCheckpoints,
        witnessPolicyDigest,
    } as const;

    return {
        ...finalityPayload,
        targetFinalityRecordDigest:
            deriveTargetFinalityRecordDigest(finalityPayload),
    };
};

const selectCountedBallots = (input: {
    readonly artifacts: readonly FullCeremonyVoterWorkerOutput[];
    readonly castArtifacts: readonly CastArtifact[];
    readonly closeRecordDigest: ProtocolDigest;
    readonly electionManifestDigest: ProtocolDigest;
    readonly pollSpecDigest: ProtocolDigest;
    readonly postVotingClosedContextDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly thresholdProfileDigest: ProtocolDigest;
    readonly votingClosedBoardHeadDigest: ProtocolDigest;
}): CountedBallotSelection => {
    const artifactByDigest = new Map(
        input.artifacts.map((artifact) => [
            artifact.publicArtifact.ballotPackageDigest,
            artifact,
        ]),
    );
    const closeOrder = { boardPosition: 0, boardSequence: 5 };
    const selectedByVoter = new Map<string, FullCeremonyVoterWorkerOutput>();
    const lateReceiptDigests: ProtocolDigest[] = [];
    const sortedCastArtifacts = [...input.castArtifacts].sort(
        (leftArtifact, rightArtifact) =>
            leftArtifact.receipt.boardSequence -
                rightArtifact.receipt.boardSequence ||
            leftArtifact.receipt.boardPosition -
                rightArtifact.receipt.boardPosition,
    );

    for (const castArtifact of sortedCastArtifacts) {
        const includedBeforeClose =
            castArtifact.receipt.boardSequence < closeOrder.boardSequence ||
            (castArtifact.receipt.boardSequence === closeOrder.boardSequence &&
                castArtifact.receipt.boardPosition < closeOrder.boardPosition);
        const artifact = artifactByDigest.get(
            castArtifact.receipt.ballotPackageDigest,
        );
        if (!includedBeforeClose || artifact === undefined) {
            lateReceiptDigests.push(castArtifact.receipt.castReceiptDigest);
            continue;
        }
        selectedByVoter.set(castArtifact.receipt.voterIdentity, artifact);
    }

    const countedArtifacts = [...selectedByVoter.values()].sort(
        (leftArtifact, rightArtifact) =>
            leftArtifact.publicArtifact.ballotPackageDigest.localeCompare(
                rightArtifact.publicArtifact.ballotPackageDigest,
            ),
    );
    const ballotSetDigest = deriveProtocolDigest('BallotSetDigest', {
        ballotPackageDigests: countedArtifacts.map(
            (artifact) => artifact.publicArtifact.ballotPackageDigest,
        ),
        closeRecordDigest: input.closeRecordDigest,
        manifestDigest: input.electionManifestDigest,
        pollSpecDigest: input.pollSpecDigest,
        postVotingClosedContextDigest: input.postVotingClosedContextDigest,
        purpose: 'm6-post-close-counted-m5-ballot-set-v1',
        rosterDigest: input.rosterDigest,
        thresholdProfileDigest: input.thresholdProfileDigest,
        votingClosedBoardHeadDigest: input.votingClosedBoardHeadDigest,
    });

    return {
        ballotSetDigest,
        countedArtifacts,
        lateReceiptDigests,
    };
};

describe('full implemented ceremony flow through the transcript-core kernel', () => {
    it('coordinates roster freeze, proof-bearing ballots, close, aggregate verification, and oracle checks', async () => {
        const roster = createFullCeremonyRoster();
        const rosterVerification = verifyRosterManifestTranscript(
            roster.rosterTranscript,
        );
        expect(rosterVerification).toMatchObject({
            ok: true,
            electionManifestDigest:
                roster.rosterTranscript.electionManifest.electionManifestDigest,
            rosterDigest: roster.rosterTranscript.electionManifest.rosterDigest,
        });
        expect(roster.frozenRosterProfile.thresholdProfile).toEqual(
            deriveThresholdProfile({ rosterSize: 20 }),
        );

        const ceremonyPublicInput = {
            ceremonyId,
            duplicateBallotPolicyDigest:
                manifestPolicyDigests.duplicateBallotPolicyDigest,
            manifestDigest:
                roster.rosterTranscript.electionManifest.electionManifestDigest,
            pollSpecDigest:
                roster.rosterTranscript.electionManifest.pollSpecDigest,
            receiverKeyProofRoot: deriveProtocolDigest('ReceiverKeyProofRoot', {
                purpose: 'full-ceremony-flow-receiver-key-proof-root',
                rosterDigest:
                    roster.rosterTranscript.electionManifest.rosterDigest,
            }),
            receiverKeyRoot: deriveProtocolDigest('EncryptedEnvelopeRoot', {
                purpose: 'full-ceremony-flow-receiver-key-root',
                rosterDigest:
                    roster.rosterTranscript.electionManifest.rosterDigest,
            }),
            rosterDigest: roster.rosterTranscript.electionManifest.rosterDigest,
            scoreDomainDigest: digest(
                'score-domain',
                roster.pollSpec.scoreDomain,
            ),
            thresholdProfileDigest:
                roster.frozenRosterProfile.thresholdProfileDigest,
            tiePolicyDigest: digest('tie-policy', roster.pollSpec.tiePolicy),
        } satisfies FullCeremonyVoterWorkerInput['ceremony'];
        const voterPlans: readonly VoterPlan[] = [
            {
                actionSequence: 1,
                normalizedScores: Array.from(
                    { length: 20 },
                    (_unusedValue, optionIndex) => ((optionIndex + 2) % 10) + 1,
                ),
                voterIdentity: 'receiver-3',
                voterRosterPosition: 3,
            },
            {
                actionSequence: 1,
                normalizedScores: Array.from(
                    { length: 20 },
                    (_unusedValue, optionIndex) =>
                        ((optionIndex * 3 + 1) % 10) + 1,
                ),
                voterIdentity: 'receiver-7',
                voterRosterPosition: 7,
            },
            {
                actionSequence: 1,
                normalizedScores: Array.from(
                    { length: 20 },
                    (_unusedValue, optionIndex) =>
                        ((optionIndex * 5 + 4) % 10) + 1,
                ),
                voterIdentity: 'receiver-11',
                voterRosterPosition: 11,
            },
            {
                actionSequence: 2,
                normalizedScores: Array.from(
                    { length: 20 },
                    (_unusedValue, optionIndex) =>
                        ((optionIndex * 7 + 6) % 10) + 1,
                ),
                voterIdentity: 'receiver-3',
                voterRosterPosition: 3,
            },
        ];
        const voterInputs = voterPlans.map((plan) =>
            buildVoterCeremonyInput({
                ceremonyPublicInput,
                manifestHead: roster.manifestHead,
                plan,
                rosterTranscript: roster.rosterTranscript,
            }),
        );
        for (const voterInput of voterInputs) {
            expect(
                verifyRosterExternalAcceptance({
                    acceptance: voterInput.rosterAcceptance,
                    expectedAcceptedBoardHeadDigest:
                        roster.manifestHead.headDigest,
                    expectedCeremonyId: ceremonyId,
                    expectedElectionManifestDigest:
                        roster.rosterTranscript.electionManifest
                            .electionManifestDigest,
                    expectedParticipantPublicKeyDigest:
                        getParticipantSigningPublicKeyDigest(
                            voterInput.rosterAcceptance.participantIdentity,
                        ),
                    expectedRosterDigest:
                        roster.rosterTranscript.electionManifest.rosterDigest,
                }).ok,
            ).toBe(true);
            expect(
                isActionCurrentForRecoveryEpoch({
                    actionContext: voterInput.actionContext,
                    expectedRosterExternalAcceptanceDigest:
                        voterInput.rosterAcceptance
                            .rosterExternalAcceptanceDigest,
                    recoveryEpochState: {
                        currentDeviceEpoch: 0,
                        currentRecoveryEpoch: 0,
                        signerIdentity: voterInput.actionContext.signerIdentity,
                    },
                }).ok,
            ).toBe(true);
        }

        const voterArtifacts = await generateVoterArtifacts({
            checkpointStore: createJsonCheckpointStore(),
            workerInputs: voterInputs.map(
                (voterInput) => voterInput.workerInput,
            ),
        });
        expect(
            new Set(
                voterArtifacts.map(
                    (artifact) => artifact.publicArtifact.ballotPackageDigest,
                ),
            ).size,
        ).toBe(voterArtifacts.length);
        for (const artifact of voterArtifacts) {
            expect(artifact.publicArtifact.packageVerification.ok).toBe(true);
            expect(JSON.stringify(artifact.publicArtifact)).not.toMatch(
                /aggregateIntegerShareVector|aggregateOpeningRandomness|projectionWitness|receiverPayloadPlaintexts|secretState|shareCommitmentOpenings|sourceWitnessCoefficients|proofWitness/u,
            );
        }

        const { castArtifacts, castHead } = createCastBoard({
            actionContexts: voterInputs.map(
                (voterInput) => voterInput.actionContext,
            ),
            artifacts: voterArtifacts,
            electionManifestDigest:
                roster.rosterTranscript.electionManifest.electionManifestDigest,
            previousHeadDigest: roster.manifestHead.headDigest,
        });
        const lateReceiptPayload = createCastReceiptPayload({
            actionContextDigest:
                voterInputs[0].actionContext.actionContextDigest,
            ballotPackageDigest:
                voterArtifacts[0].publicArtifact.ballotPackageDigest,
            boardPosition: 0,
            boardSequence: 6,
            electionManifestDigest:
                roster.rosterTranscript.electionManifest.electionManifestDigest,
            voterIdentity: voterArtifacts[0].publicArtifact.voterIdentity,
        });
        const lateReceiptDigest = deriveCastReceiptDigest(lateReceiptPayload);
        const postVotingClosedContextDigest =
            derivePostVotingClosedContextDigest({
                ceremonyId,
                closeRecordDigest: digest('close-record-placeholder'),
                electionManifestDigest:
                    roster.rosterTranscript.electionManifest
                        .electionManifestDigest,
                votingClosedBoardHeadDigest: castHead.headDigest,
            });
        const closeRecordDigest = deriveCloseRecordDigest({
            objectType: 'CloseRecord',
            objectVersion: 1,
            boardPosition: 0,
            boardSequence: 5,
            ceremonyId,
            closeKind: 'VotingClosed',
            closedBoardHeadDigest: castHead.headDigest,
            electionManifestDigest:
                roster.rosterTranscript.electionManifest.electionManifestDigest,
            organizerIdentity:
                roster.rosterTranscript.electionManifest.signature.signedRoot
                    .signerIdentity,
        });
        const finalPostVotingClosedContextDigest =
            derivePostVotingClosedContextDigest({
                ceremonyId,
                closeRecordDigest,
                electionManifestDigest:
                    roster.rosterTranscript.electionManifest
                        .electionManifestDigest,
                votingClosedBoardHeadDigest: castHead.headDigest,
            });
        expect(postVotingClosedContextDigest).not.toBe(
            finalPostVotingClosedContextDigest,
        );
        const { head: closeHead, inclusionProofs: closeInclusionProofs } =
            createBoardHeadWithObjects(
                5,
                castHead.headDigest,
                [
                    {
                        boardPosition: 0,
                        objectDigest: closeRecordDigest,
                        objectType: 'CloseRecord',
                    },
                ],
                'full-ceremony-flow',
            );
        const closeRecord = createCloseRecord({
            boardHeadDigest: closeHead.headDigest,
            boardPosition: 0,
            boardSequence: 5,
            closedBoardHeadDigest: castHead.headDigest,
            electionManifestDigest:
                roster.rosterTranscript.electionManifest.electionManifestDigest,
            organizerIdentity:
                roster.rosterTranscript.electionManifest.signature.signedRoot
                    .signerIdentity,
            postVotingClosedContextDigest: finalPostVotingClosedContextDigest,
        });
        expect(closeRecord.closeRecordDigest).toBe(closeRecordDigest);
        const { head: lateHead, inclusionProofs: lateInclusionProofs } =
            createBoardHeadWithObjects(
                6,
                closeHead.headDigest,
                [
                    {
                        boardPosition: 0,
                        objectDigest: lateReceiptDigest,
                        objectType: 'CastReceipt',
                    },
                ],
                'full-ceremony-flow',
            );
        const signedLateReceipt = signCastReceipt({
            boardHeadDigest: lateHead.headDigest,
            payload: lateReceiptPayload,
        });
        const boardEvidence = createBoardEvidence([
            ...roster.boardEvidence.signedBoardHeads,
            castHead,
            closeHead,
            lateHead,
        ]);
        const allCastArtifacts = [
            ...castArtifacts,
            {
                inclusionProof: lateInclusionProofs[0],
                publicArtifact: voterArtifacts[0].publicArtifact,
                receipt: signedLateReceipt,
            },
        ];
        for (const castArtifact of allCastArtifacts) {
            expect(
                verifyCastReceiptShell({
                    boardEvidence,
                    expectedElectionManifestDigest:
                        roster.rosterTranscript.electionManifest
                            .electionManifestDigest,
                    expectedVoterPublicKeyDigest:
                        getParticipantSigningPublicKeyDigest(
                            castArtifact.receipt.voterIdentity,
                        ),
                    receipt: castArtifact.receipt,
                    receiptInclusionProof: castArtifact.inclusionProof,
                }).ok,
            ).toBe(true);
        }
        expect(closeInclusionProofs[0].includedObjectDigest).toBe(
            closeRecord.closeRecordDigest,
        );
        const acceptedPostVotingClosedContextDigest = requireValue(
            closeRecord.postVotingClosedContextDigest ?? undefined,
            'Voting close record should carry a post-voting closed context digest.',
        );

        const selection = selectCountedBallots({
            artifacts: voterArtifacts,
            castArtifacts: allCastArtifacts,
            closeRecordDigest: closeRecord.closeRecordDigest,
            electionManifestDigest:
                roster.rosterTranscript.electionManifest.electionManifestDigest,
            pollSpecDigest:
                roster.rosterTranscript.electionManifest.pollSpecDigest,
            postVotingClosedContextDigest:
                acceptedPostVotingClosedContextDigest,
            rosterDigest: roster.rosterTranscript.electionManifest.rosterDigest,
            thresholdProfileDigest:
                roster.frozenRosterProfile.thresholdProfileDigest,
            votingClosedBoardHeadDigest: castHead.headDigest,
        });
        const reversedSelection = selectCountedBallots({
            artifacts: [...voterArtifacts].reverse(),
            castArtifacts: [...allCastArtifacts].reverse(),
            closeRecordDigest: closeRecord.closeRecordDigest,
            electionManifestDigest:
                roster.rosterTranscript.electionManifest.electionManifestDigest,
            pollSpecDigest:
                roster.rosterTranscript.electionManifest.pollSpecDigest,
            postVotingClosedContextDigest:
                acceptedPostVotingClosedContextDigest,
            rosterDigest: roster.rosterTranscript.electionManifest.rosterDigest,
            thresholdProfileDigest:
                roster.frozenRosterProfile.thresholdProfileDigest,
            votingClosedBoardHeadDigest: castHead.headDigest,
        });
        expect(selection.ballotSetDigest).toBe(
            reversedSelection.ballotSetDigest,
        );
        expect(selection.countedArtifacts).toHaveLength(3);
        expect(selection.lateReceiptDigests).toContain(
            signedLateReceipt.castReceiptDigest,
        );
        expect(
            selection.countedArtifacts.filter(
                (artifact) =>
                    artifact.publicArtifact.voterIdentity === 'receiver-3',
            ),
        ).toEqual([
            requireValue(
                voterArtifacts.find(
                    (artifact) =>
                        artifact.publicArtifact.voterIdentity ===
                            'receiver-3' &&
                        artifact.oracleScoreMetadata.normalizedScores[0] === 7,
                ),
                'Missing replacement receiver-3 ballot artifact.',
            ),
        ]);

        const countedPackages = selection.countedArtifacts.map(
            (artifact) => artifact.publicArtifact.ballotPackage,
        );
        const contributorAcceptance = createRosterExternalAcceptance({
            acceptedBoardHeadDigest: roster.manifestHead.headDigest,
            electionManifestDigest:
                roster.rosterTranscript.electionManifest.electionManifestDigest,
            participantIdentity: 'receiver-1',
            rosterDigest: roster.rosterTranscript.electionManifest.rosterDigest,
        });
        const contributorActionContext = createActionContext({
            actionSequence: 1,
            boardHead: castHead,
            contextDigest: acceptedPostVotingClosedContextDigest,
            electionManifestDigest:
                roster.rosterTranscript.electionManifest.electionManifestDigest,
            rosterExternalAcceptanceDigest:
                contributorAcceptance.rosterExternalAcceptanceDigest,
            signerIdentity: 'receiver-1',
        });
        const { aggregateCommitment, statement } =
            buildAggregateDerivationStatement({
                ballotPackages: countedPackages,
                closeRecordDigest: closeRecord.closeRecordDigest,
                contributorActionContextDigest:
                    contributorActionContext.actionContextDigest,
                contributorIdentity: 'receiver-1',
                contributorRosterExternalAcceptanceDigest:
                    contributorAcceptance.rosterExternalAcceptanceDigest,
                contributorRosterPosition: 1,
                postVotingClosedContextDigest:
                    acceptedPostVotingClosedContextDigest,
                votingClosedBoardHeadDigest: castHead.headDigest,
            });
        expect(statement.ballotSetDigest).toBe(selection.ballotSetDigest);
        expect(() =>
            buildAggregateDerivationStatement({
                ballotPackages: [countedPackages[0], countedPackages[0]],
                closeRecordDigest: closeRecord.closeRecordDigest,
                contributorActionContextDigest:
                    contributorActionContext.actionContextDigest,
                contributorIdentity: 'receiver-1',
                contributorRosterExternalAcceptanceDigest:
                    contributorAcceptance.rosterExternalAcceptanceDigest,
                contributorRosterPosition: 1,
                postVotingClosedContextDigest:
                    acceptedPostVotingClosedContextDigest,
                votingClosedBoardHeadDigest: castHead.headDigest,
            }),
        ).toThrow(/duplicates/u);

        const aggregateWitness = sumAggregateDerivationWitnesses({
            witnesses: selection.countedArtifacts.map(
                (artifact) => artifact.contributorWitness,
            ),
        });
        const plaintextOracle = derivePlaintextTopKOracle({
            ballots: selection.countedArtifacts.map((artifact) => ({
                scores: artifact.oracleScoreMetadata.normalizedScores,
                voterIdentity: artifact.oracleScoreMetadata.voterIdentity,
            })),
            maximumRosterSize: 20,
            pollSpec: roster.pollSpec,
        });
        expect(
            aggregateWitness.aggregateIntegerShareVector.filter(
                (_coordinate, coordinateIndex) => coordinateIndex % 11 === 0,
            ),
        ).toEqual(plaintextOracle.tally.optionTallies);

        const profileSet = createBallotPrivacyProfileSet({ optionCount: 20 });
        const certificate = createShareCommitmentMessageBoundCert({
            maximumCanonicalTurnout: 20,
            shareCommitmentProfile: profileSet.shareCommitmentProfile,
        });
        expect(certificate.shareCommitmentMessageBoundCertDigest).toBe(
            statement.shareCommitmentMessageBoundCertDigest,
        );
        const proofBuild = buildAggregateDerivationProofInput({
            aggregateCommitment,
            statement,
            witness: aggregateWitness,
        });
        const kernel = await loadTranscriptCoreKernel();
        const generatedAggregateProof = kernel.generateAggregateDerivationProof(
            {
                proofInput: proofBuild.proofInput,
                proverRandomnessHex: deterministicRandomnessHex(
                    'aggregate-derivation-proof',
                ),
                secretState: proofBuild.secretState,
            },
        );
        expect(generatedAggregateProof).toMatchObject({
            ok: true,
            generatedProofBytes: true,
            operation: 'generateAggregateDerivationProof',
            unresolvedReason: null,
        });
        const aggregateComponent = createAggregateDerivationComponent({
            aggregateCommitment,
            proofBytesHex: String(generatedAggregateProof.proofBytesHex),
            proofInput: proofBuild.proofInput,
            shareCommitmentMessageBoundCert: certificate,
            statement,
        });
        expect(JSON.stringify(aggregateComponent)).not.toMatch(
            /aggregateIntegerShareVector|aggregateOpeningRandomness|receiverPlaintext|sourceWitnessCoefficients|proofWitness/u,
        );
        expect(
            kernel.verifyAggregateDerivationProof({
                closeRecord,
                component: aggregateComponent,
                contributorActionContext,
                countedBallotPackages: countedPackages,
            }),
        ).toMatchObject({
            ok: true,
            operation: 'verifyAggregateDerivationProof',
            unresolvedReason: null,
        });

        const staleRosterPackage = {
            ...countedPackages[0],
            ballotProofStatement: {
                ...countedPackages[0].ballotProofStatement,
                rosterDigest: digest('stale-roster'),
            },
        } satisfies ClaimBearingBallotPackage;
        expect(
            kernel.verifyClaimBearingBallotPackage({
                ballotPackage: staleRosterPackage,
            }).ok,
        ).toBe(false);
        const mismatchedComponentPackage = {
            ...countedPackages[1],
            componentProofBundle: countedPackages[0].componentProofBundle,
            componentProofInputs: countedPackages[0].componentProofInputs,
        } satisfies ClaimBearingBallotPackage;
        expect(
            kernel.verifyClaimBearingBallotPackage({
                ballotPackage: mismatchedComponentPackage,
            }).ok,
        ).toBe(false);

        const topKEvaluationRecordDigest = deriveProtocolDigest(
            'TopKEvaluationRecordDigest',
            {
                aggregateDerivationComponentDigest:
                    aggregateComponent.aggregateDerivationComponentDigest,
                oracleDigest: plaintextOracle.oracleDigest,
                purpose: 'full-ceremony-flow-plaintext-oracle-shell-evaluation',
            },
        );
        const {
            head: targetEvaluationHead,
            inclusionProofs: targetEvaluationInclusionProofs,
        } = createBoardHeadWithObjects(
            7,
            lateHead.headDigest,
            [
                {
                    boardPosition: 0,
                    objectDigest: topKEvaluationRecordDigest,
                    objectType: 'TopKEvaluationRecord',
                },
            ],
            'full-ceremony-flow',
        );
        const finalityRecord = createTargetFinalityRecordForOracle({
            finalizedHead: targetEvaluationHead,
            manifestDigest:
                roster.rosterTranscript.electionManifest.electionManifestDigest,
            topKEvaluationInclusionProof: targetEvaluationInclusionProofs[0],
            topKEvaluationRecordDigest,
        });
        const finalityVerification = verifyTargetFinality({
            boardEvidence: createBoardEvidence([
                ...boardEvidence.signedBoardHeads,
                targetEvaluationHead,
            ]),
            record: finalityRecord,
            targetFinalityPolicy,
            witnessPolicy,
            witnessPublicKeyDigests,
        });
        expect(finalityVerification).toMatchObject({
            ok: true,
            targetFinalityRecordDigest:
                finalityRecord.targetFinalityRecordDigest,
        });
    }, 7_200_000);
});
