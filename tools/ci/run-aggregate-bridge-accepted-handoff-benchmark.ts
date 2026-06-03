import { mkdir } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';

import {
    createContribution,
    currentRecoveryEpochMap,
    setupParticipants,
} from './encrypted-aggregate-bridge-matrix/fixtures.js';
import {
    matrixMarkdown,
    writeArtifact,
} from './encrypted-aggregate-bridge-matrix/reporting.js';
import {
    claimTierForRosterSize,
    outputDirectory,
    publicArtifactIsWitnessClean,
    roundedMilliseconds,
    variantKey,
    type MatrixRow,
    type Variant,
} from './encrypted-aggregate-bridge-matrix/shared.js';

import { canonicalJson, deriveProtocolHash } from '#packages/crypto/src/index';
import {
    createAggregateReadyRecord,
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
    selectFirstValidAggregateContributions,
    verifyAggregateReadyRecordStructure,
} from '#packages/protocol/src/ballot-privacy/index';
import { deriveThresholdProfile } from '#packages/protocol/src/lifecycle/thresholds';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import {
    runMandatoryBallotProofRecordBenchmark,
    type RuntimeBenchmarkContext,
} from '#tests/support/ballot-privacy-proof-benchmarks';
import {
    createJsonCheckpointStore,
    shouldResumeFromTestCheckpoints,
} from '#tests/support/node-test-checkpoints';

const acceptedHandoffVariant: Variant = {
    optionCount: 20,
    rosterSize: 20,
};

type AcceptedHandoffReport = {
    readonly aggregateReadyConstructionMilliseconds: number;
    readonly aggregateReadyRecordHash: string;
    readonly aggregateReadyVerificationMilliseconds: number;
    readonly ballotPackageVerificationMilliseconds: number;
    readonly benchmarkRows: readonly MatrixRow[];
    readonly contributionCount: number;
    readonly evidenceBoundary: string;
    readonly mandatoryBallotProofBytes: number;
    readonly mandatoryBallotProofGenerationMilliseconds: number;
    readonly mandatoryBallotProofVerificationMilliseconds: number;
    readonly negativeBoundary: string;
    readonly proofByteLength: number;
    readonly runtime: RuntimeBenchmarkContext;
    readonly status: 'passed';
};

const nodeRuntimeContext = (): RuntimeBenchmarkContext => ({
    deviceClass: 'node',
    runtimeLabel: `node-${process.version}`,
});

const acceptedHandoffMarkdown = (report: AcceptedHandoffReport): string => {
    const benchmarkRow = report.benchmarkRows[0];
    const lines = [
        '# Encrypted aggregate bridge accepted-package handoff benchmark',
        '',
        `Status: ${report.status}`,
        `Runtime: ${report.runtime.runtimeLabel}`,
        `Evidence boundary: ${report.evidenceBoundary}`,
        `Negative boundary: ${report.negativeBoundary}`,
        '',
        '| n | m | selected | proof bytes | prover ms | verifier ms | aggregate-ready construction ms | aggregate-ready verifier ms | witness-clean |',
        '| -: | -: | -: | -: | -: | -: | -: | -: | - |',
        benchmarkRow === undefined
            ? ''
            : [
                  benchmarkRow.rosterSize,
                  benchmarkRow.optionCount,
                  benchmarkRow.selectedContributionCount,
                  benchmarkRow.proofByteLength,
                  benchmarkRow.proverTime.toFixed(1),
                  benchmarkRow.verifierTime.toFixed(1),
                  report.aggregateReadyConstructionMilliseconds,
                  report.aggregateReadyVerificationMilliseconds,
                  benchmarkRow.publicArtifactWitnessCleanResult
                      ? 'passed'
                      : 'failed',
              ].join(' | '),
        '',
        '| mandatory ballot proof bytes | ballot proof generation ms | ballot proof verification ms | package verification ms | aggregate-ready hash |',
        '| -: | -: | -: | -: | - |',
        [
            report.mandatoryBallotProofBytes,
            report.mandatoryBallotProofGenerationMilliseconds,
            report.mandatoryBallotProofVerificationMilliseconds,
            report.ballotPackageVerificationMilliseconds,
            report.aggregateReadyRecordHash,
        ].join(' | '),
        '',
    ];

    return `${lines.join('\n')}\n`;
};

const main = async (): Promise<void> => {
    const kernel = await loadTranscriptCoreKernel();
    const runtime = nodeRuntimeContext();
    const mandatoryBenchmark = runMandatoryBallotProofRecordBenchmark({
        checkpoints: createJsonCheckpointStore(),
        kernel,
        resumeFromCheckpoints: shouldResumeFromTestCheckpoints(),
        runtime,
    });
    const thresholdProfile = deriveThresholdProfile({
        casualMicroRosterAcknowledged: false,
        rosterSize: acceptedHandoffVariant.rosterSize,
    });
    const trusteeAggregateThreshold = thresholdProfile.pvssThreshold;
    const profileSet = createBallotPrivacyProfileSet({
        optionCount: acceptedHandoffVariant.optionCount,
    });
    const certificate = createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: acceptedHandoffVariant.rosterSize,
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
    const setupPackage = kernel.generateBgvPassiveSetup({
        ceremonyId: mandatoryBenchmark.fixture.statement.ceremonyId,
        manifestHash: mandatoryBenchmark.fixture.statement.manifestHash,
        participants: setupParticipants(acceptedHandoffVariant.rosterSize),
        rosterHash: mandatoryBenchmark.fixture.statement.rosterHash,
        setupSeed: `encrypted-aggregate-bridge-accepted-handoff-${variantKey(
            acceptedHandoffVariant,
        )}`,
        thresholdProfileHash:
            mandatoryBenchmark.fixture.statement.thresholdProfileHash,
    }) as Record<string, unknown>;
    if (setupPackage.ok === false) {
        throw new Error(
            `Accepted handoff setup generation failed: ${canonicalJson(setupPackage)}`,
        );
    }
    const aggregateSelectionPolicyHash = deriveProtocolHash(
        'ChallengeDomainHash',
        {
            optionCount: acceptedHandoffVariant.optionCount,
            purpose:
                'encrypted-aggregate-bridge-accepted-handoff-selection-policy-v1',
            rosterSize: acceptedHandoffVariant.rosterSize,
            thresholdProfileHash:
                mandatoryBenchmark.fixture.statement.thresholdProfileHash,
        },
    );
    const bridgeWitnessPrivacyProfileHash = deriveProtocolHash(
        'ChallengeDomainHash',
        {
            optionCount: acceptedHandoffVariant.optionCount,
            purpose:
                'encrypted-aggregate-bridge-accepted-handoff-witness-privacy-v1',
            rosterSize: acceptedHandoffVariant.rosterSize,
        },
    );
    const heParamHash = deriveProtocolHash('ChallengeDomainHash', {
        optionCount: acceptedHandoffVariant.optionCount,
        purpose: 'encrypted-aggregate-bridge-accepted-handoff-he-param-v1',
        rosterSize: acceptedHandoffVariant.rosterSize,
    });
    const contributions = [];
    let proofByteLength = 0;
    let proverTime = 0;
    let verifierTime = 0;
    let bridgeEncryptionWitnessClean = true;

    for (
        let contributorRosterPosition = 1;
        contributorRosterPosition <= trusteeAggregateThreshold;
        contributorRosterPosition += 1
    ) {
        const contribution = createContribution({
            aggregateSelectionPolicyHash,
            ballotPackage: mandatoryBenchmark.ballotPackage,
            bridgeWitnessPrivacyProfileHash,
            certificate,
            contributorRosterPosition,
            fixture: mandatoryBenchmark.fixture,
            heParamHash,
            kernel,
            setupPackage,
            casualMicroRosterAcknowledged: false,
            contributionMode: 'checked-accepted-counted-package',
            variant: acceptedHandoffVariant,
        });
        if (contribution.aggregateContribution === null) {
            throw new Error(
                'Accepted-package handoff benchmark did not produce a checked aggregate contribution.',
            );
        }
        contributions.push(contribution.aggregateContribution);
        proofByteLength += contribution.proofByteLength;
        proverTime += roundedMilliseconds(contribution.proverTime);
        verifierTime += roundedMilliseconds(contribution.verifierTime);
        bridgeEncryptionWitnessClean =
            bridgeEncryptionWitnessClean &&
            publicArtifactIsWitnessClean(contribution.bridgeEncryption);
    }
    const firstContribution = contributions[0];
    if (firstContribution === undefined) {
        throw new Error(
            'Accepted handoff benchmark produced no contributions.',
        );
    }
    const selection = selectFirstValidAggregateContributions({
        aggregateContributionQuorum: trusteeAggregateThreshold,
        contributions,
        currentRecoveryEpochMap: currentRecoveryEpochMap(contributions),
        expectedAggregateSelectionPolicyHash: aggregateSelectionPolicyHash,
        requiredPostVotingClosedContextHash:
            firstContribution.postVotingClosedContextHash,
    });
    if (!selection.ok || selection.firstValidOrderHash === undefined) {
        throw new Error(
            `Accepted handoff contribution selection failed: ${canonicalJson(selection)}`,
        );
    }
    const aggregateReadyConstructionStartedAt = performance.now();
    const aggregateReadyRecord = createAggregateReadyRecord({
        aggregateContributionQuorum: trusteeAggregateThreshold,
        firstValidOrderHash: selection.firstValidOrderHash,
        rosterSize: acceptedHandoffVariant.rosterSize,
        selectedContributions: selection.selectedContributions,
    });
    const aggregateReadyConstructionMilliseconds = roundedMilliseconds(
        performance.now() - aggregateReadyConstructionStartedAt,
    );
    const aggregateReadyVerificationStartedAt = performance.now();
    const aggregateReadyVerification =
        verifyAggregateReadyRecordStructure(aggregateReadyRecord);
    const aggregateReadyVerificationMilliseconds = roundedMilliseconds(
        performance.now() - aggregateReadyVerificationStartedAt,
    );
    if (!aggregateReadyVerification.ok) {
        throw new Error(
            `Accepted handoff aggregate-ready verification failed: ${canonicalJson(
                aggregateReadyVerification,
            )}`,
        );
    }
    const benchmarkRow: MatrixRow = {
        aggregateCoordinateCount:
            mandatoryBenchmark.fixture.statement.shareVectorWidth,
        aggregateReadyVerificationTime: aggregateReadyVerificationMilliseconds,
        ciphertextShape: {
            basisId: 'sealed-lattice-bgv-rns-data-basis-v1',
            coefficientCount: 32_768,
            level: 15,
            slotCount: 32_768,
        },
        claimTier: claimTierForRosterSize(acceptedHandoffVariant.rosterSize),
        failureReason: null,
        optionCount: acceptedHandoffVariant.optionCount,
        proofByteLength,
        proverTime,
        publicArtifactWitnessCleanResult: publicArtifactIsWitnessClean({
            aggregateReadyRecord,
            bridgeEncryptionWitnessClean,
            contributions,
        }),
        rosterSize: acceptedHandoffVariant.rosterSize,
        selectedContributionCount: trusteeAggregateThreshold,
        shareVectorWidth: mandatoryBenchmark.fixture.statement.shareVectorWidth,
        status: 'passed',
        thresholdProfileHash:
            mandatoryBenchmark.fixture.statement.thresholdProfileHash,
        trusteeAggregateThreshold,
        verifierTime,
    };
    const report: AcceptedHandoffReport = {
        aggregateReadyConstructionMilliseconds,
        aggregateReadyRecordHash: aggregateReadyRecord.aggregateReadyRecordHash,
        aggregateReadyVerificationMilliseconds,
        ballotPackageVerificationMilliseconds: roundedMilliseconds(
            mandatoryBenchmark.report.packageVerificationMs,
        ),
        benchmarkRows: [benchmarkRow],
        contributionCount: contributions.length,
        evidenceBoundary:
            'checked aggregate-ready handoff from proof-byte-bearing mandatory accepted ballot package; not final bridge acceptance',
        mandatoryBallotProofBytes: mandatoryBenchmark.report.proofSizeBytes,
        mandatoryBallotProofGenerationMilliseconds: roundedMilliseconds(
            mandatoryBenchmark.report.generationMs,
        ),
        mandatoryBallotProofVerificationMilliseconds: roundedMilliseconds(
            mandatoryBenchmark.report.verificationMs,
        ),
        negativeBoundary:
            'negative matrix remains synthetic relation evidence; this report covers accepted-package positive handoff only',
        proofByteLength,
        runtime,
        status: 'passed',
    };

    await mkdir(outputDirectory, { recursive: true });
    await writeArtifact(
        'aggregate-bridge-accepted-handoff-report.json',
        `${canonicalJson(report)}\n`,
    );
    await writeArtifact(
        'aggregate-bridge-accepted-handoff-report.md',
        acceptedHandoffMarkdown(report),
    );
    await writeArtifact(
        'aggregate-bridge-accepted-handoff-benchmark-report.md',
        matrixMarkdown({
            rows: report.benchmarkRows,
            title: 'Encrypted aggregate bridge accepted-package handoff benchmark',
        }),
    );
    console.log(acceptedHandoffMarkdown(report));
};

await main();
