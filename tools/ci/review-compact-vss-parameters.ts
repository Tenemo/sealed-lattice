import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { deriveProtocolHash } from '#packages/crypto/src/index.js';
import {
    compactVssCarryClaimMaskDigitCount,
    compactVssCommitmentMeasurement,
    compactVssDigitClaimMaskDigitCount,
    compactVssMessageDigitBase,
    compactVssMessageDigitCount,
    compactVssMessageDigitTritCount,
    compactVssParameterCertificateInputBinding,
    targetDecryptionAggregateMessageClaimMaskDigitCount,
    targetDecryptionSmudgingMessageClaimMaskDigitCount,
} from '#packages/protocol/src/setup/compact-vss-commitments.js';
import {
    sameSecretAnchorArgument,
    sameSecretBoundProofFamilies,
    sameSecretProofFamily,
    sameSecretRelation,
    setupProofProfileId,
} from '#packages/protocol/src/setup/same-secret-consistency-records.js';
import {
    acceptedBgvProfileRingDegree,
    acceptedBgvSetupQSharePrimes,
} from '#packages/protocol/src/setup/vss-coefficient-commitments.js';
import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

type JsonValue =
    | boolean
    | null
    | number
    | string
    | readonly JsonValue[]
    | { readonly [key: string]: JsonValue };

type JsonRecord = Readonly<Record<string, JsonValue>>;

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const artifactPath = path.resolve(
    repoRoot,
    process.env.SEALED_LATTICE_COMPACT_VSS_PARAMETER_REVIEW_PATH ??
        'tests/fixtures/compact-vss-parameter-review-results.json',
);
const expectedArtifactCanonicalSha256 =
    'd99367759b76f8e6d5cf01bc6284bdc7a8a201791da4a06899f95580026854c1';

const participantCount = 10;
const thresholdDegree = 4;
const canonicalTargetCiphertextLevel = 4;
const selectedEvaluatorWorkingLevel = 15;
const currentFullCoefficientTransportBytes = 1_604_341_697;
const targetRnsPrimes = acceptedBgvSetupQSharePrimes.slice(
    0,
    canonicalTargetCiphertextLevel + 1,
);
const residueByteCount = 8;
const minimumPublicCommitmentReductionFactor = 2_800;
const canonicalTargetBasis = {
    objectType: 'CanonicalTargetBasis',
    objectVersion: 1,
    basisId: 'sealed-lattice-bgv-rns-data-basis-v1',
    targetLevel: canonicalTargetCiphertextLevel,
    primeOrder: 'profile-order-prefix',
    targetPrimes: targetRnsPrimes,
    modulusSwitchSchedule: {
        sourceWorkingLevel: selectedEvaluatorWorkingLevel,
        terminalLevel: canonicalTargetCiphertextLevel,
        rule: 'drop trailing data-basis primes until the terminal target level is reached',
    },
    scalingNormalization:
        'normalize ciphertext decrypt scaling to one before target roots are computed',
    targetCiphertextRule:
        'target id and target order ciphertexts must both use the canonical target level',
} as const satisfies JsonRecord;

const sameSecretProofFamilyBindingPayload = {
    objectType: 'SameSecretProofFamilyBinding',
    objectVersion: 1,
    setupProfileId: 'CollectiveBgvSetup-v1',
    setupProofProfileId,
    proofFamily: sameSecretProofFamily,
    sameSecretRelation,
    anchorArgument: sameSecretAnchorArgument,
    boundSecretDependentProofFamilies: sameSecretBoundProofFamilies,
} as const satisfies JsonRecord;

const assertRecord = (value: unknown, pathName: string): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${pathName} must be an object.`);
    }

    return value as JsonRecord;
};

const assertArray = (
    value: unknown,
    pathName: string,
): readonly JsonValue[] => {
    if (!Array.isArray(value)) {
        throw new Error(`${pathName} must be an array.`);
    }

    return value as readonly JsonValue[];
};

const assertNumber = (value: unknown, pathName: string): number => {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        throw new Error(`${pathName} must be a finite number.`);
    }

    return value;
};

const rowsWithId = (
    rows: readonly JsonValue[],
    rowId: string,
): readonly JsonRecord[] =>
    rows.filter((row): row is JsonRecord => {
        if (typeof row !== 'object' || row === null || Array.isArray(row)) {
            return false;
        }

        return (row as JsonRecord).rowId === rowId;
    });

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

const normalizedJsonText = (value: JsonValue): string =>
    `${JSON.stringify(sortJsonValue(value), null, 4)}\n`;

const normalizedJsonFileText = (filePath: string): string =>
    normalizedJsonText(JSON.parse(readFileSync(filePath, 'utf8')) as JsonValue);

const sha256Hex = (text: string): string =>
    createHash('sha256').update(text, 'utf8').digest('hex');

const log2 = (value: number): number => Math.log2(value);

const sourceMessageRows = (input: {
    readonly commitmentImageLog2: number;
    readonly commitmentModulusCount: number;
    readonly outputCoordinateCount: number;
    readonly commitmentModulusLog2Sum: number;
}): readonly JsonRecord[] =>
    acceptedBgvSetupQSharePrimes.map((sourceRnsPrime, rnsLimbIndex) => {
        const messageDomainLog2 =
            acceptedBgvProfileRingDegree * log2(sourceRnsPrime);
        const domainImageGapLog2 =
            messageDomainLog2 - input.commitmentImageLog2;
        const minimumOutputCoordinateCountByCounting = Math.ceil(
            messageDomainLog2 / input.commitmentModulusLog2Sum,
        );
        const minimumSingleCommitmentBodyBytesByCounting =
            minimumOutputCoordinateCountByCounting *
            input.commitmentModulusCount *
            residueByteCount;

        return {
            rnsLimbIndex,
            sourceRnsPrime,
            messageDomainLog2,
            commitmentImageLog2: input.commitmentImageLog2,
            domainImageGapLog2,
            currentOutputCoordinateCount: input.outputCoordinateCount,
            minimumOutputCoordinateCountByCounting,
            minimumSingleCommitmentBodyBytesByCounting,
        };
    });

const activeCompactMessageColumnReview = (input: {
    readonly commitmentModulusLimbs: readonly {
        readonly commitmentModulusIndex: number;
        readonly modulus: number;
    }[];
    readonly outputCoordinateCount: number;
    readonly ringDegree: number;
    readonly messageCoverageTermsPerCoordinate: number;
    readonly randomnessProjectionWeight: number;
    readonly randomnessWidth: number;
    readonly coordinateCountPerCommitment: number;
    readonly totalCommitments: number;
    readonly largestSourceRnsPrime: number;
    readonly smallestCommitmentModulus: number;
    readonly currentSingleCommitmentBodyBytes: number;
    readonly currentTotalPublicCommitmentBytes: number;
    readonly currentReductionFactor: number;
    readonly currentResidueMultiplyAddsPerCommitment: number;
    readonly currentTotalResidueArithmeticOperations: number;
    readonly aggregatePublicSumResidueAdditions: number;
    readonly publicSetupDownloadBudgetBytes: number;
}): JsonRecord => {
    const activeInputColumnLabels = [
        ...Array.from(
            { length: compactVssMessageDigitCount },
            (_unused, digitIndex) => `message:${String(digitIndex)}`,
        ),
        ...Array.from(
            { length: input.randomnessWidth },
            (_unused, randomnessColumnIndex) =>
                `randomness:${String(randomnessColumnIndex)}`,
        ),
    ];
    const decodedRangeExclusive =
        compactVssMessageDigitBase ** BigInt(compactVssMessageDigitCount);
    const largestFreshMessageCoefficientExclusive = input.largestSourceRnsPrime;
    const largestAggregateMessageCoefficientExclusive =
        participantCount * input.largestSourceRnsPrime;
    const randomnessMatrixResiduesPerCoordinate =
        input.randomnessWidth * input.randomnessProjectionWeight;
    const sampledMatrixResiduesPerCoordinate =
        compactVssMessageDigitCount * input.messageCoverageTermsPerCoordinate +
        randomnessMatrixResiduesPerCoordinate;
    const messageMatrixResiduesPerCommitment =
        compactVssMessageDigitCount * input.ringDegree;
    const randomnessMatrixResiduesPerCommitment =
        input.coordinateCountPerCommitment *
        randomnessMatrixResiduesPerCoordinate;
    const sampledMatrixResiduesPerCommitment =
        messageMatrixResiduesPerCommitment +
        randomnessMatrixResiduesPerCommitment;
    const activeResidueMultiplyAddsPerCommitment =
        sampledMatrixResiduesPerCommitment;
    const activeTotalResidueMultiplyAdds =
        activeResidueMultiplyAddsPerCommitment * input.totalCommitments;
    const activeTotalResidueArithmeticOperations =
        activeTotalResidueMultiplyAdds +
        input.aggregatePublicSumResidueAdditions;
    const estimatorColumnDifferenceInfinityBound =
        compactVssMessageDigitBase - 1n;
    const estimatorRequiredStrictUpperBound = BigInt(
        (input.smallestCommitmentModulus - 1) / 2,
    );

    return {
        finding:
            'The active compact commitment uses two base-3^17 message digit columns with deterministic full-coordinate coverage plus the existing sampled randomness columns: this preserves the compact public body while removing the absent-message-coordinate blocker.',
        activationInterpretation:
            'This row records the active source constants and the proof obligations still blocking target-ready result release; it is not production activation evidence by itself.',
        activeConstruction:
            'encode each carried message coefficient as two little-endian base-3^17 digits, assign every coefficient in each digit column to one compact coordinate, and keep randomness columns sampled by the public projection index; share-linkage, same-secret bridge, and target-decryption rows bind those digits through masked consistency claims and verifier-side trit decoder columns',
        messageDigitBaseDecimal: compactVssMessageDigitBase.toString(),
        messageDigitCount: compactVssMessageDigitCount,
        messageDigitTritCount: compactVssMessageDigitTritCount,
        activeInputColumnLabels,
        decodedRangeExclusiveDecimal: decodedRangeExclusive.toString(),
        decodedRangeBits:
            compactVssMessageDigitCount *
            compactVssMessageDigitTritCount *
            log2(3),
        largestFreshMessageCoefficientExclusive,
        largestAggregateMessageCoefficientExclusive,
        aggregateDecodedRangeSlackDecimal: (
            decodedRangeExclusive -
            BigInt(largestAggregateMessageCoefficientExclusive)
        ).toString(),
        commitmentBodyBytes: {
            currentSingleCommitmentBodyBytes:
                input.currentSingleCommitmentBodyBytes,
            activeSingleCommitmentBodyBytes:
                input.currentSingleCommitmentBodyBytes,
            currentTotalPublicCommitmentBytes:
                input.currentTotalPublicCommitmentBytes,
            activeTotalPublicCommitmentBytes:
                input.currentTotalPublicCommitmentBytes,
            currentReductionFactor: input.currentReductionFactor,
            activeReductionFactor: input.currentReductionFactor,
            publicSetupDownloadFraction:
                input.currentTotalPublicCommitmentBytes /
                input.publicSetupDownloadBudgetBytes,
        },
        cpuWorkModel: {
            currentResidueMultiplyAddsPerCommitment:
                input.currentResidueMultiplyAddsPerCommitment,
            activeResidueMultiplyAddsPerCommitment,
            perCommitmentMultiplyAddFactor:
                activeResidueMultiplyAddsPerCommitment /
                input.currentResidueMultiplyAddsPerCommitment,
            currentTotalResidueArithmeticOperations:
                input.currentTotalResidueArithmeticOperations,
            activeTotalResidueArithmeticOperations,
            totalResidueArithmeticFactor:
                activeTotalResidueArithmeticOperations /
                input.currentTotalResidueArithmeticOperations,
            aggregatePublicSumResidueAdditions:
                input.aggregatePublicSumResidueAdditions,
        },
        relationSamplingShape: {
            messageCoverageTermsPerCoordinate:
                input.messageCoverageTermsPerCoordinate,
            randomnessProjectionWeight: input.randomnessProjectionWeight,
            messageMatrixResiduesPerCommitment,
            randomnessMatrixResiduesPerCoordinate,
            randomnessMatrixResiduesPerCommitment,
            sampledMatrixResiduesPerCoordinate,
            sampledMatrixResiduesPerCommitment,
        },
        estimatorPreconditionReview: {
            estimator:
                'malb/lattice-estimator SIS lattice row, after relation review accounts for full-message witness differences and relation L1 norms',
            estimatorColumnDifferenceInfinityBoundDecimal:
                estimatorColumnDifferenceInfinityBound.toString(),
            estimatorRequiredStrictUpperBoundDecimal:
                estimatorRequiredStrictUpperBound.toString(),
            activeColumnPreconditionMarginDecimal: (
                estimatorRequiredStrictUpperBound -
                estimatorColumnDifferenceInfinityBound
            ).toString(),
            interpretation:
                'The digit columns avoid the full-residue witness bound only where verifier-checked proof constraints bind them as bounded digits. The source-bound review input now records direct digit, carry, target direct-digit, target masked-claim norm rows, and reviewed conclusion rows for the current covered relation; final public release still needs accepted compact setup, target proof material, production smudging evidence, final measurement, and supported-runtime evidence.',
        },
        proofRangeEvidenceModel: {
            committedMessageColumns: compactVssMessageDigitCount,
            publicCommitmentInputColumnCount: activeInputColumnLabels.length,
            directDigitClaimEvidence: {
                appliedRows: [
                    'compact share-linkage',
                    'compact same-secret bridge',
                    'target-decryption share',
                ],
                digitBoundMechanism:
                    'masked consistency claims bind each committed message digit and verifier-side trit decoder columns bind each digit to its base-3 decomposition',
                carryClaimMaskDigitCount: compactVssCarryClaimMaskDigitCount,
                messageDigitClaimMaskDigitCount:
                    compactVssDigitClaimMaskDigitCount,
            },
            targetDirectDigitClaimEvidence: {
                appliedRows: ['target-decryption share'],
                digitBoundMechanism:
                    'target-decryption message digits are committed as digit columns, each digit column is bound by a masked consistency claim, and verifier-side trit decoder columns bind each digit to its base-3 decomposition',
                aggregateMessageClaimMaskDigitCount:
                    targetDecryptionAggregateMessageClaimMaskDigitCount,
                smudgingMessageClaimMaskDigitCount:
                    targetDecryptionSmudgingMessageClaimMaskDigitCount,
            },
            interpretation:
                'Direct digit claims are proof evidence, not extra compact public commitment body columns. They must stay measured before activation, but they keep the public commitment body at two message columns plus two randomness columns.',
        },
        implementationWorkRequired: [
            'keep the reviewed conclusion rows source-derived and recomputed by accepted setup when the compact relation or witness bounds change',
            'measure proof-material byte size, proof generation time, and proof verification time on the final compact proof path',
            'keep target-result release development-only until supported-runtime evidence is measured through the public package boundary from source constants',
        ],
        sampledMatrixResiduesPerCoordinate,
        sampledMatrixResiduesPerCommitment,
    };
};

const replacementCpuBudgetReview = (input: {
    readonly commitmentModulusLimbs: readonly {
        readonly commitmentModulusIndex: number;
        readonly modulus: number;
    }[];
    readonly outputCoordinateCount: number;
    readonly messageCoverageTermsPerCoordinate: number;
    readonly randomnessProjectionWeight: number;
    readonly randomnessWidth: number;
    readonly ringDegree: number;
    readonly totalCommitments: number;
    readonly currentResidueMultiplyAddsPerCommitment: number;
    readonly currentTotalResidueArithmeticOperations: number;
    readonly aggregatePublicSumResidueAdditions: number;
}): JsonRecord => {
    const inputColumnCount =
        compactVssMessageDigitCount + input.randomnessWidth;
    const naiveFullSupportResidueMultiplyAddsPerCommitment =
        input.commitmentModulusLimbs.length *
        input.outputCoordinateCount *
        input.ringDegree *
        inputColumnCount;
    const naiveFullSupportTotalResidueMultiplyAdds =
        naiveFullSupportResidueMultiplyAddsPerCommitment *
        input.totalCommitments;
    const naiveFullSupportTotalResidueArithmeticOperations =
        naiveFullSupportTotalResidueMultiplyAdds +
        input.aggregatePublicSumResidueAdditions;

    return {
        finding:
            'A naive dense all-column linear replacement is still rejected because it would cover message and randomness columns by multiplying compact commitment work up to the full ring degree.',
        decision:
            'Keep the covered-message relation for measurement and review unless the final certificate review demands a different relation; do not switch to a dense all-column relation without accepting its measured CPU cost.',
        currentRelation: {
            inputColumnCount,
            messageCoverageTermsPerCoordinate:
                input.messageCoverageTermsPerCoordinate,
            randomnessProjectionWeight: input.randomnessProjectionWeight,
            residueMultiplyAddsPerCommitment:
                input.currentResidueMultiplyAddsPerCommitment,
            totalResidueArithmeticOperations:
                input.currentTotalResidueArithmeticOperations,
        },
        rejectedNaiveFullSupportRelation: {
            candidateProjectionWeight: input.ringDegree,
            residueMultiplyAddsPerCommitment:
                naiveFullSupportResidueMultiplyAddsPerCommitment,
            perCommitmentMultiplyAddFactor:
                naiveFullSupportResidueMultiplyAddsPerCommitment /
                input.currentResidueMultiplyAddsPerCommitment,
            totalResidueArithmeticOperations:
                naiveFullSupportTotalResidueArithmeticOperations,
            totalResidueArithmeticFactor:
                naiveFullSupportTotalResidueArithmeticOperations /
                input.currentTotalResidueArithmeticOperations,
        },
        requiredReplacementShape:
            'Any replacement must cover every verifier-accepted message coordinate and retain measured CPU within the compact path budget; acceptable candidates need a reviewed covered linear relation, a structured vector commitment, or a shorter proof-bound accepted message object with measured proof costs.',
    };
};

const compactProofActivationReview = (): JsonRecord => ({
    finding:
        'The compact commitment profile is active in the commitment computation and compact proof relations, and the source-derived certificate conclusion rows are now bound by the parameter review. Public target-result release is exposed only as development evidence until supported-runtime evidence is measured through the public package boundary.',
    currentVerifierFacts: [
        'compact share-linkage row checks cover compact opening randomness plus direct message-digit, carry consistency, and verifier-side trit decoder claims',
        'compact same-secret bridge vectors consume message projections, direct digit consistency claims, and verifier-side trit decoder rows tying target messages to secret + target_prime * negative_indicator',
        'target-decryption share proofs consume message projections, released-share relations, and masked consistency claims on each committed message digit',
        'prover-side witness validation and opening-input range checks remain input hygiene; load-bearing range evidence comes from verifier-checked direct digit claim bounds',
    ],
    unsafeShortcut:
        'Do not promote the active compact profile to target-result release by relying on honest-prover range checks, private opening validation, or documentation-only range bounds.',
    requiredProofChanges: [
        'review the exact final relation, including correlated multi-opening exposure and the final range-evidence cost',
        'measure the converted source-batch proof-material byte size and proof generation and verification times',
        'keep public target-result release connected to regenerated certificate input bindings through the published SDK wrapper',
    ],
    implementationConsequence:
        'Accepted setup rejects incomplete compact material as incomplete, rejects malformed complete compact material as malformed, and lets proof-verified complete compact material proceed to later setup phases; target-result release remains development evidence until supported-runtime evidence is measured through the public package boundary.',
});

const artifact = (): JsonRecord => {
    const targetBasisHash = deriveProtocolHash(
        'TargetBasisHash',
        canonicalTargetBasis,
    );
    const sameSecretProofFamilyBindingRoot = deriveProtocolHash(
        'SameSecretProofFamilyBindingRoot',
        sameSecretProofFamilyBindingPayload,
    );
    const sourceBinding = compactVssParameterCertificateInputBinding({
        participantCount,
        sourceRnsPrimes: acceptedBgvSetupQSharePrimes,
        targetRnsPrimes,
        thresholdDegree,
        targetBasisHash,
        sameSecretProofFamilyBindingRoot,
    });
    const commitmentRelation = assertRecord(
        sourceBinding.commitmentRelation,
        'sourceBinding.commitmentRelation',
    );
    const commitmentModulusLimbs = assertArray(
        commitmentRelation.commitmentModulusLimbs,
        'sourceBinding.commitmentRelation.commitmentModulusLimbs',
    ).map((entry, limbIndex) => {
        const limb = assertRecord(
            entry,
            `sourceBinding.commitmentRelation.commitmentModulusLimbs.${String(limbIndex)}`,
        );

        return {
            commitmentModulusIndex: assertNumber(
                limb.commitmentModulusIndex,
                `commitmentModulusLimbs.${String(limbIndex)}.commitmentModulusIndex`,
            ),
            modulus: assertNumber(
                limb.modulus,
                `commitmentModulusLimbs.${String(limbIndex)}.modulus`,
            ),
        };
    });
    const outputCoordinateCount = assertNumber(
        commitmentRelation.outputCoordinateCount,
        'sourceBinding.commitmentRelation.outputCoordinateCount',
    );
    const coordinateCountPerCommitment = assertNumber(
        commitmentRelation.coordinateCountPerCommitment,
        'sourceBinding.commitmentRelation.coordinateCountPerCommitment',
    );
    const messageCoverageTermsPerCoordinate = assertNumber(
        commitmentRelation.messageCoverageTermsPerCoordinate,
        'sourceBinding.commitmentRelation.messageCoverageTermsPerCoordinate',
    );
    const randomnessProjectionWeight = assertNumber(
        commitmentRelation.randomnessProjectionWeight,
        'sourceBinding.commitmentRelation.randomnessProjectionWeight',
    );
    const messageWidth = assertNumber(
        commitmentRelation.messageWidth,
        'sourceBinding.commitmentRelation.messageWidth',
    );
    const randomnessWidth = assertNumber(
        commitmentRelation.randomnessWidth,
        'sourceBinding.commitmentRelation.randomnessWidth',
    );
    const commitmentModulusLog2Sum = commitmentModulusLimbs.reduce(
        (sum, limb) => sum + log2(limb.modulus),
        0,
    );
    const commitmentImageLog2 =
        outputCoordinateCount * commitmentModulusLog2Sum;
    const messageRows = sourceMessageRows({
        commitmentImageLog2,
        commitmentModulusCount: commitmentModulusLimbs.length,
        outputCoordinateCount,
        commitmentModulusLog2Sum,
    });
    const largestCountingGapRow = messageRows.reduce((largest, row) =>
        assertNumber(row.domainImageGapLog2, 'domainImageGapLog2') >
        assertNumber(largest.domainImageGapLog2, 'domainImageGapLog2')
            ? row
            : largest,
    );
    const measurement = compactVssCommitmentMeasurement({
        participantCount,
        sourceRnsLimbCount: acceptedBgvSetupQSharePrimes.length,
        targetRnsLimbCount: targetRnsPrimes.length,
        thresholdDegree,
        currentFullCoefficientTransportBytes,
    });
    const totalCommitments = assertNumber(
        measurement.cpuWorkModel.totalCommitments,
        'measurement.cpuWorkModel.totalCommitments',
    );
    const minimumOutputCoordinateCountByCounting = assertNumber(
        largestCountingGapRow.minimumOutputCoordinateCountByCounting,
        'largestCountingGapRow.minimumOutputCoordinateCountByCounting',
    );
    const minimumSingleCommitmentBodyBytesByCounting =
        minimumOutputCoordinateCountByCounting *
        commitmentModulusLimbs.length *
        residueByteCount;
    const minimumTotalPublicCommitmentBytesByCounting =
        minimumSingleCommitmentBodyBytesByCounting * totalCommitments;
    const minimumCountingReductionFactor =
        currentFullCoefficientTransportBytes /
        minimumTotalPublicCommitmentBytesByCounting;
    const largestSourceRnsPrime = Math.max(...acceptedBgvSetupQSharePrimes);
    const smallestCommitmentModulus = Math.min(
        ...commitmentModulusLimbs.map((limb) => limb.modulus),
    );
    const estimatorFullMessageDifferenceInfinityBound =
        largestSourceRnsPrime - 1;
    const estimatorRequiredStrictUpperBound =
        (smallestCommitmentModulus - 1) / 2;
    const parameterReviewInputs = assertRecord(
        sourceBinding.parameterReviewInputs,
        'sourceBinding.parameterReviewInputs',
    );
    const moduleSisBindingRows = assertArray(
        parameterReviewInputs.moduleSisBindingRows,
        'sourceBinding.parameterReviewInputs.moduleSisBindingRows',
    );
    const moduleLweHidingRows = assertArray(
        parameterReviewInputs.moduleLweHidingRows,
        'sourceBinding.parameterReviewInputs.moduleLweHidingRows',
    );
    const structuredRingRows = assertArray(
        parameterReviewInputs.structuredRingRows,
        'sourceBinding.parameterReviewInputs.structuredRingRows',
    );
    const multiOpeningRows = assertArray(
        parameterReviewInputs.multiOpeningRows,
        'sourceBinding.parameterReviewInputs.multiOpeningRows',
    );
    const proofExtractionRows = assertArray(
        parameterReviewInputs.proofExtractionRows,
        'sourceBinding.parameterReviewInputs.proofExtractionRows',
    );
    const certificateConclusionRows = assertArray(
        parameterReviewInputs.certificateConclusionRows,
        'sourceBinding.parameterReviewInputs.certificateConclusionRows',
    );

    return {
        objectType: 'CompactVssParameterReview',
        objectVersion: 15,
        command:
            'pnpm exec tsx ./tools/ci/review-compact-vss-parameters.ts --check-artifact',
        artifactCanonicalization:
            'recursively sorted JSON object keys, four-space indentation, trailing newline',
        sourceBinding: {
            objectType: sourceBinding.objectType,
            objectVersion: sourceBinding.objectVersion,
            setupProfileId: sourceBinding.setupProfileId,
            profileId: sourceBinding.profileId,
            compactVssParameterCertificateInputBindingHash:
                sourceBinding.compactVssParameterCertificateInputBindingHash,
            targetBasisHash,
            sameSecretProofFamilyBindingRoot,
            compactMaterialArtifactBoundary:
                sourceBinding.compactMaterialArtifactBoundary as JsonValue,
        },
        exactInputRows: {
            parameterReviewInputs,
            estimatorInputRows: sourceBinding.estimatorInputRows as JsonValue,
        },
        bindingDimensionReview: {
            finding:
                'The current covered compact linear body still needs a certificate-grade binding argument for arbitrary coefficient-vector messages: after fixing the opening randomness, the full message domain is far larger than the compact commitment image.',
            countingInterpretation:
                'This counting row proves non-injectivity of the full-message map at fixed randomness, not an efficient short-collision attack by itself. A computational binding claim still needs a reviewed short-SIS reduction for the actual witness-difference bounds.',
            ringDegree: sourceBinding.ringDegree,
            messageWidth,
            randomnessWidth,
            commitmentModulusLimbs,
            currentOutputCoordinateCount: outputCoordinateCount,
            currentSingleCommitmentBodyBytes:
                measurement.singleCompactCommitmentBytes,
            currentTotalPublicCommitmentBytes:
                measurement.totalCompactPublicCommitmentBytes,
            currentReductionFactor: measurement.byteReduction.reductionFactor,
            largestCountingGapRow,
            sourceMessageRows: messageRows,
        },
        messageCoordinateCoverageReview: assertRecord(
            parameterReviewInputs.messageCoordinateCoverageReview,
            'sourceBinding.parameterReviewInputs.messageCoordinateCoverageReview',
        ),
        moduleSisBindingInputReview: {
            finding:
                'The source binding now carries exact Module-SIS review input rows for the covered-message relation, including digit bounds, randomness bounds, proof-extracted rows, and multi-opening exposure. This is input evidence, not a final binding certificate.',
            rows: moduleSisBindingRows as JsonValue,
            proofExtractionRows: proofExtractionRows as JsonValue,
            multiOpeningRows: multiOpeningRows as JsonValue,
        },
        moduleLweHidingInputReview: {
            finding:
                'The source binding now carries exact Module-LWE review input rows for final public commitment exposure, correlated openings, corrupted-recipient opening credentials, randomness projection samples, and structured-ring scope. This is input evidence, not a final hiding certificate.',
            rows: moduleLweHidingRows as JsonValue,
        },
        structuredRingInputReview: {
            finding:
                'The source binding now names the final negacyclic module ring and matrix derivation domains that any binding and hiding estimate must cover.',
            rows: structuredRingRows as JsonValue,
        },
        multiOpeningInputReview: {
            finding:
                'The source binding now counts the final commitment and opening exposure used by the multi-opening loss and corrupted-recipient hiding review.',
            rows: multiOpeningRows as JsonValue,
        },
        certificateConclusionReview: {
            finding:
                'The source binding now carries reviewed binding, hiding, structured-ring, and multi-opening conclusion rows for the covered-message relation. Accepted setup recomputes these rows through the setup commitment security certificate before compact material can pass the setup verifier.',
            rows: certificateConclusionRows as JsonValue,
        },
        activeCompactMessageColumnReview: activeCompactMessageColumnReview({
            commitmentModulusLimbs,
            outputCoordinateCount,
            ringDegree: sourceBinding.ringDegree,
            messageCoverageTermsPerCoordinate,
            randomnessProjectionWeight,
            randomnessWidth,
            coordinateCountPerCommitment,
            totalCommitments,
            largestSourceRnsPrime,
            smallestCommitmentModulus,
            currentSingleCommitmentBodyBytes:
                measurement.singleCompactCommitmentBytes,
            currentTotalPublicCommitmentBytes:
                measurement.totalCompactPublicCommitmentBytes,
            currentReductionFactor: measurement.byteReduction.reductionFactor,
            currentResidueMultiplyAddsPerCommitment:
                measurement.cpuWorkModel.residueMultiplyAddsPerCommitment,
            currentTotalResidueArithmeticOperations:
                measurement.cpuWorkModel.totalResidueArithmeticOperations,
            aggregatePublicSumResidueAdditions:
                measurement.cpuWorkModel.aggregatePublicSumResidueAdditions,
            publicSetupDownloadBudgetBytes:
                measurement.budgetComparison.publicSetupDownloadBudgetBytes,
        }),
        replacementCpuBudgetReview: replacementCpuBudgetReview({
            commitmentModulusLimbs,
            outputCoordinateCount,
            messageCoverageTermsPerCoordinate,
            randomnessProjectionWeight,
            randomnessWidth,
            ringDegree: sourceBinding.ringDegree,
            totalCommitments,
            currentResidueMultiplyAddsPerCommitment:
                measurement.cpuWorkModel.residueMultiplyAddsPerCommitment,
            currentTotalResidueArithmeticOperations:
                measurement.cpuWorkModel.totalResidueArithmeticOperations,
            aggregatePublicSumResidueAdditions:
                measurement.cpuWorkModel.aggregatePublicSumResidueAdditions,
        }),
        compactProofActivationReview: compactProofActivationReview(),
        countingSafeLowerBound: {
            finding:
                'If this linear construction kept unrestricted coefficient-vector messages and sought injectivity by output dimension alone, it would need this many output coordinates before the image is even large enough; this lower bound alone breaks the compact public-body budget.',
            minimumOutputCoordinateCountByCounting,
            minimumSingleCommitmentBodyBytesByCounting,
            totalCommitments,
            minimumTotalPublicCommitmentBytesByCounting,
            minimumCountingReductionFactor,
            minimumPublicCommitmentReductionFactor,
            publicSetupDownloadBudgetBytes:
                measurement.budgetComparison.publicSetupDownloadBudgetBytes,
            publicSetupDownloadFractionAtCountingLowerBound:
                minimumTotalPublicCommitmentBytesByCounting /
                measurement.budgetComparison.publicSetupDownloadBudgetBytes,
        },
        retiredFullCoefficientSisEstimatorReview: {
            finding:
                'The retired full-coefficient binding interpretation cannot certify the compact body because valid full-RNS message differences exceed the SIS estimator precondition. This row remains as a regression guard only; the active covered relation is certified through verifier-checked base-3^17 digit columns.',
            estimator: 'malb/lattice-estimator SIS lattice row',
            estimatorSource:
                'reference-projects/lattice-estimator/estimator/sis_lattice.py',
            estimatorPrecondition:
                'SIS length_bound must be strictly less than (q - 1) / 2; otherwise the estimator reports the instance as trivially easy.',
            estimatorFullMessageDifferenceInfinityBound,
            estimatorRequiredStrictUpperBound,
            preconditionExcess:
                estimatorFullMessageDifferenceInfinityBound -
                estimatorRequiredStrictUpperBound,
        },
        moduleSisBindingConclusionReview: {
            finding:
                'The active binding conclusion is over the verifier-checked digit witness, not over unrestricted full-RNS message differences. The bound digit difference satisfies the estimator smallness precondition by a large source-derived margin before any lattice-reduction cost estimate is interpreted.',
            conclusionRows: rowsWithId(
                certificateConclusionRows,
                'compact-vss-covered-message-module-sis-binding-conclusion',
            ) as JsonValue,
        },
        moduleLweHidingConclusionReview: {
            finding:
                'The active hiding conclusion is scoped to the final public compact-commitment exposure, balanced-ternary randomness source, corrupted-recipient opening view, and structured-ring row carried by the source binding.',
            conclusionRows: rowsWithId(
                certificateConclusionRows,
                'compact-vss-covered-message-module-lwe-hiding-conclusion',
            ) as JsonValue,
        },
        replacementRequirement: {
            finding:
                'The compact commitment certificate gate is now represented by source-derived conclusion rows. Positive target-result release still needs accepted compact setup, same-secret bridge acceptance, target proof material, production smudging evidence, final measurement, and supported-runtime evidence.',
            profileIdentifierRule:
                'keep this construction-specific profile identifier bound to the covered-message relation and rerun the review if the relation or witness bounds change',
        },
        activationGate: {
            finding:
                'Public target-result activation remains scoped to development evidence until supported-runtime evidence is complete.',
            currentVerifierRule:
                'Absent compact VSS public material may remain optional, incomplete compact material must refuse as incomplete, malformed complete compact material must refuse as malformed, and proof-verified compact setup material may proceed to later setup phases; public target-result acceptance is available only through the proof-backed SDK wrapper as development evidence.',
            requiredReplacementEvidence: [
                'accepted-setup verification over compact public material and compact same-secret bridge material',
                'recipient-owned restored witness verification against the accepted compact artifact',
                'target-decryption proof material and production smudging evidence',
                'public release verification for proof-backed target shares',
                'final compact measurement that reports public commitment-body bytes, proof-material bytes, private mailbox bytes, target proof bytes, generation time, verification time, and supported-runtime evidence',
            ],
        },
    };
};

const main = (): void => {
    const output = normalizedJsonText(artifact());

    if (process.argv.includes('--write-artifact')) {
        mkdirSync(path.dirname(artifactPath), { recursive: true });
        writeFileSync(artifactPath, output);
    }

    if (process.argv.includes('--check-artifact')) {
        const expected = normalizedJsonFileText(artifactPath);
        if (output !== expected) {
            throw new Error(
                `${artifactPath} does not match the review output.`,
            );
        }
        const outputHash = sha256Hex(output);
        if (outputHash !== expectedArtifactCanonicalSha256) {
            throw new Error(
                `${artifactPath} canonical SHA-256 mismatch: expected ${expectedArtifactCanonicalSha256}, got ${outputHash}`,
            );
        }
    }

    process.stdout.write(output);
};

if (isDirectlyInvokedModule(import.meta.url)) {
    main();
}
