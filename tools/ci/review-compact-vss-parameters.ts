import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { deriveProtocolHash } from '#packages/crypto/src/index.js';
import {
    compactVssCommitmentMeasurement,
    compactVssParameterCertificateInputBinding,
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
    '4233b0cbb34b278ca49769768714a6a2530d1f93b586f521570dffb5d84be9cc';

const participantCount = 10;
const thresholdDegree = 4;
const canonicalTargetCiphertextLevel = 6;
const selectedEvaluatorWorkingLevel = 15;
const currentFullCoefficientTransportBytes = 1_604_341_697;
const targetRnsPrimes = acceptedBgvSetupQSharePrimes.slice(
    0,
    canonicalTargetCiphertextLevel + 1,
);
const residueByteCount = 8;
const minimumPublicCommitmentReductionFactor = 2_800;
const candidateMessageDigitTritCount = 17;
const candidateMessageDigitBase = 3 ** candidateMessageDigitTritCount;
const candidateMessageDigitCount = 2;

const tritCountForBound = (boundExclusive: number): number => {
    if (!Number.isSafeInteger(boundExclusive) || boundExclusive <= 0) {
        throw new Error('trit bound must be a positive safe integer.');
    }
    let representedBound = 1;
    let tritCount = 0;
    while (representedBound < boundExclusive) {
        representedBound *= 3;
        if (!Number.isSafeInteger(representedBound)) {
            throw new Error('trit bound exceeded the safe integer range.');
        }
        tritCount += 1;
    }

    return tritCount;
};

const highDigitTritCountForMessageBound = (
    messageBoundExclusive: number,
): number =>
    tritCountForBound(
        Math.ceil(messageBoundExclusive / candidateMessageDigitBase),
    );

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

const sparseProjectionCoverageReview = (input: {
    readonly coordinateCountPerCommitment: number;
    readonly messageWidth: number;
    readonly projectionWeight: number;
    readonly ringDegree: number;
}): JsonRecord => {
    const sampledMessageProjectionTermsPerCommitment =
        input.coordinateCountPerCommitment *
        input.messageWidth *
        input.projectionWeight;
    const sampledMessageProjectionTermsPerMessageColumn =
        input.coordinateCountPerCommitment * input.projectionWeight;
    const maximumDistinctMessageCoefficientsCoveredPerMessageColumn = Math.min(
        input.ringDegree,
        sampledMessageProjectionTermsPerMessageColumn,
    );
    const minimumUncoveredMessageCoefficientsPerMessageColumn = Math.max(
        0,
        input.ringDegree -
            maximumDistinctMessageCoefficientsCoveredPerMessageColumn,
    );
    const maximumMessageColumnCoverageFraction =
        maximumDistinctMessageCoefficientsCoveredPerMessageColumn /
        input.ringDegree;

    return {
        finding:
            'The current sparse projection cannot bind full message vectors because each commitment body samples far fewer message positions than the ring degree; regardless of seed and ignoring duplicate samples, many message coefficients are absent from every public coordinate.',
        interpretation:
            'Any coefficient index absent from all message-column projections can be changed while holding opening randomness fixed without changing the compact commitment body.',
        ringDegree: input.ringDegree,
        messageWidth: input.messageWidth,
        projectionWeight: input.projectionWeight,
        coordinateCountPerCommitment: input.coordinateCountPerCommitment,
        sampledMessageProjectionTermsPerCommitment,
        sampledMessageProjectionTermsPerMessageColumn,
        maximumDistinctMessageCoefficientsCoveredPerMessageColumn,
        minimumUncoveredMessageCoefficientsPerMessageColumn,
        maximumMessageColumnCoverageFraction,
        replacementImplication:
            'A replacement construction must bind every operative message coefficient through the commitment/proof relation, not merely tune estimator rows for the current sparse sampler.',
    };
};

const digitEncodedReplacementReview = (input: {
    readonly commitmentModulusLimbs: readonly {
        readonly commitmentModulusIndex: number;
        readonly modulus: number;
    }[];
    readonly outputCoordinateCount: number;
    readonly projectionWeight: number;
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
    const candidateInputColumnLabels = [
        ...Array.from(
            { length: candidateMessageDigitCount },
            (_unused, digitIndex) => `message:${String(digitIndex)}`,
        ),
        ...Array.from(
            { length: input.randomnessWidth },
            (_unused, randomnessColumnIndex) =>
                `randomness:${String(randomnessColumnIndex)}`,
        ),
    ];
    const candidateDecodedRangeExclusive =
        candidateMessageDigitBase ** candidateMessageDigitCount;
    const largestFreshMessageCoefficientExclusive = input.largestSourceRnsPrime;
    const largestAggregateMessageCoefficientExclusive =
        participantCount * input.largestSourceRnsPrime;
    const freshHighDigitTritCount = highDigitTritCountForMessageBound(
        largestFreshMessageCoefficientExclusive,
    );
    const aggregateHighDigitTritCount = highDigitTritCountForMessageBound(
        largestAggregateMessageCoefficientExclusive,
    );
    const freshTritColumnsPerMessageVector =
        candidateMessageDigitTritCount + freshHighDigitTritCount;
    const aggregateTritColumnsPerMessageVector =
        candidateMessageDigitTritCount + aggregateHighDigitTritCount;
    const sampledMatrixResiduesPerCoordinate =
        candidateInputColumnLabels.length * input.projectionWeight;
    const sampledMatrixResiduesPerCommitment =
        input.coordinateCountPerCommitment * sampledMatrixResiduesPerCoordinate;
    const candidateResidueMultiplyAddsPerCommitment =
        input.commitmentModulusLimbs.length *
        input.outputCoordinateCount *
        input.projectionWeight *
        candidateInputColumnLabels.length;
    const candidateTotalResidueMultiplyAdds =
        candidateResidueMultiplyAddsPerCommitment * input.totalCommitments;
    const candidateTotalResidueArithmeticOperations =
        candidateTotalResidueMultiplyAdds +
        input.aggregatePublicSumResidueAdditions;
    const estimatorDigitDifferenceInfinityBound = candidateMessageDigitBase - 1;
    const estimatorRequiredStrictUpperBound =
        (input.smallestCommitmentModulus - 1) / 2;

    return {
        finding:
            'A fixed two-digit message encoding is active in the compact commitment and proof relations: it keeps the existing compact body size while making committed message columns short enough for a meaningful Module-SIS binding review.',
        activationInterpretation:
            'This row records the active digit-encoding profile and the proof obligations that must be closed before compact public material can be accepted; it is not accepted setup evidence by itself.',
        candidateConstruction:
            'encode each message coefficient as two little-endian base-3^17 digits, commit both digit columns plus the existing two randomness columns, prove the low digit with 17 ternary columns and the high digit with the statement-bound trit count, and make every proof relation decode digit[0] + digit[1] * 3^17 before comparing VSS, same-secret, and target-decryption messages',
        messageDigitBase: candidateMessageDigitBase,
        messageDigitCount: candidateMessageDigitCount,
        messageDigitTritCount: candidateMessageDigitTritCount,
        candidateInputColumnLabels,
        decodedRangeExclusive: candidateDecodedRangeExclusive,
        decodedRangeBits: log2(candidateDecodedRangeExclusive),
        largestFreshMessageCoefficientExclusive,
        largestAggregateMessageCoefficientExclusive,
        aggregateDecodedRangeSlack:
            candidateDecodedRangeExclusive -
            largestAggregateMessageCoefficientExclusive,
        commitmentBodyBytes: {
            currentSingleCommitmentBodyBytes:
                input.currentSingleCommitmentBodyBytes,
            candidateSingleCommitmentBodyBytes:
                input.currentSingleCommitmentBodyBytes,
            currentTotalPublicCommitmentBytes:
                input.currentTotalPublicCommitmentBytes,
            candidateTotalPublicCommitmentBytes:
                input.currentTotalPublicCommitmentBytes,
            currentReductionFactor: input.currentReductionFactor,
            candidateReductionFactor: input.currentReductionFactor,
            publicSetupDownloadFraction:
                input.currentTotalPublicCommitmentBytes /
                input.publicSetupDownloadBudgetBytes,
        },
        cpuWorkModel: {
            currentResidueMultiplyAddsPerCommitment:
                input.currentResidueMultiplyAddsPerCommitment,
            candidateResidueMultiplyAddsPerCommitment,
            perCommitmentMultiplyAddFactor:
                candidateResidueMultiplyAddsPerCommitment /
                input.currentResidueMultiplyAddsPerCommitment,
            currentTotalResidueArithmeticOperations:
                input.currentTotalResidueArithmeticOperations,
            candidateTotalResidueArithmeticOperations,
            totalResidueArithmeticFactor:
                candidateTotalResidueArithmeticOperations /
                input.currentTotalResidueArithmeticOperations,
            aggregatePublicSumResidueAdditions:
                input.aggregatePublicSumResidueAdditions,
        },
        estimatorPreconditionReview: {
            estimator:
                'malb/lattice-estimator SIS lattice row, after relation review accounts for decoder weights and relation L1 norms',
            estimatorDigitDifferenceInfinityBound,
            estimatorRequiredStrictUpperBound,
            digitColumnPreconditionMargin:
                estimatorRequiredStrictUpperBound -
                estimatorDigitDifferenceInfinityBound,
            interpretation:
                'The digit columns avoid the full-residue witness bound that invalidates the current sparse profile only if the verifier receives load-bearing evidence that hidden message openings are bounded digits. Final certification still needs digit-bound evidence, exact weighted relation norms, and a reviewed hiding row for the final public sample count.',
        },
        proofRangeEvidenceModel: {
            digitBoundMechanism:
                'each committed message digit is accompanied inside the proof trace by ternary columns checked with the existing M(M - 1)(M - 2) row constraint; the low digit always uses 17 trits and the high digit uses the statement-bound count',
            digitDecoderRelation:
                'digit = sum_{position=0}^{tritCount - 1} trit[position] * 3^position',
            lowDigitTritColumns: candidateMessageDigitTritCount,
            freshHighDigitTritColumns: freshHighDigitTritCount,
            aggregateHighDigitTritColumns: aggregateHighDigitTritCount,
            freshTritColumnsPerMessageVector,
            aggregateTritColumnsPerMessageVector,
            committedMessageDigitColumns: candidateMessageDigitCount,
            publicCommitmentInputColumnCount: candidateInputColumnLabels.length,
            freshRangeProofInputColumnCountPerMessageVector:
                freshTritColumnsPerMessageVector,
            aggregateRangeProofInputColumnCountPerMessageVector:
                aggregateTritColumnsPerMessageVector,
            interpretation:
                'The extra ternary columns are proof evidence, not compact public commitment body columns. They increase proof width and must be measured before activation, but they keep the public commitment body at two message columns plus two randomness columns.',
        },
        implementationWorkRequired: [
            'complete a certificate-grade Module-SIS binding review for the exact digit decoder weights, relation L1 norms, and multi-opening witness differences',
            'complete a Module-LWE hiding review for the final four-column public sample count, correlated openings, corrupted-recipient leakage model, and multi-opening loss',
            'bind accepted-setup verification to the regenerated compact parameter certificate before allowing complete compact public material to pass accepted setup',
            'measure proof-material byte size, proof generation time, and proof verification time on the converted source-batch proof path',
            'keep accepted setup fail-closed until the replacement review artifact, measurement evidence, and accepted-setup certificate binding are all generated from source constants',
        ],
        sampledMatrixResiduesPerCoordinate,
        sampledMatrixResiduesPerCommitment,
    };
};

const digitProofActivationReview = (): JsonRecord => ({
    finding:
        'The two-digit commitment profile is active in the compact commitment computation and the compact proof relations, but it is not accepted-setup evidence until the final binding, hiding, measurement, and certificate-binding rows are closed.',
    currentVerifierFacts: [
        'compact share-linkage row checks cover compact opening randomness, claim-mask digits, 17 low-digit trits for each hidden message, and the statement-bound high-digit trits for that message class',
        'compact share-linkage masked consistency claims bind only the lifted carry columns across commitment fields',
        'compact same-secret bridge vectors consume message digit projections, decoder linchecks, and a decoded relation tying target messages to secret + target_prime * negative_indicator',
        'target-decryption share proofs consume digit projections, decoder linchecks, decoded aggregate and smudging relations, and masked consistency claims on the decoded messages',
        'prover-side witness validation and opening-input range checks remain input hygiene; the load-bearing range evidence is the verifier-checked trit decomposition inside the proof',
    ],
    unsafeShortcut:
        'Do not promote the candidate to accepted setup by relying on honest-prover range checks, private opening validation, or documentation-only digit bounds.',
    requiredProofChanges: [
        'review the exact final relation, including decoder weights, relation L1 norms, range-evidence cost, and correlated multi-opening exposure',
        'measure the converted source-batch proof-material byte size and proof generation and verification times',
        'connect accepted-setup compact material acceptance to regenerated certificate input bindings instead of the current fail-closed refusal',
    ],
    implementationConsequence:
        'Accepted setup must remain fail-closed for complete compact VSS public material until the source-derived review artifact, measurement evidence, and accepted-setup certificate binding are regenerated from the final constants.',
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
    const projectionWeight = assertNumber(
        commitmentRelation.projectionWeight,
        'sourceBinding.commitmentRelation.projectionWeight',
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

    return {
        objectType: 'CompactVssParameterReview',
        objectVersion: 7,
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
        },
        exactInputRows: {
            parameterReviewInputs,
            estimatorInputRows: sourceBinding.estimatorInputRows as JsonValue,
        },
        bindingDimensionReview: {
            finding:
                'The current sparse linear body has no certificate-grade binding argument for arbitrary coefficient-vector messages: after fixing the opening randomness, the full message domain is far larger than the compact commitment image.',
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
        sparseProjectionCoverageReview: sparseProjectionCoverageReview({
            coordinateCountPerCommitment,
            messageWidth,
            projectionWeight,
            ringDegree: sourceBinding.ringDegree,
        }),
        digitEncodedReplacementReview: digitEncodedReplacementReview({
            commitmentModulusLimbs,
            outputCoordinateCount,
            projectionWeight,
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
        digitProofActivationReview: digitProofActivationReview(),
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
        moduleSisEstimatorReview: {
            finding:
                'The available computational binding interpretation would have to reduce collisions to a short-SIS instance, but the exact full-message row cannot be certified because valid message differences are not short and exceed the estimator precondition before lattice reduction is considered.',
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
        moduleLweHidingReview: {
            finding:
                'The hiding review is not a final certificate row for the current profile because the binding construction must change first; the replacement review must rerun Module-LWE estimates for the final sample count, modulus limbs, and opening distribution.',
            requiredFinalInputs:
                'final commitment image dimension, public sample count, correlated opening model, corrupted-recipient leakage model, and multi-opening loss',
        },
        replacementRequirement: {
            finding:
                'To reach certificate-grade compact setup material, complete the binding and hiding review for the active short-message digit commitment and its verifier-checked decoder evidence.',
            profileIdentifierRule:
                'keep the current construction-specific profile identifier fail-closed until the replacement parameter review is complete',
        },
        activationGate: {
            finding:
                'Accepted setup and target-result verification must stay fail-closed for complete compact VSS public material until the active digit relation has certificate-grade binding, hiding, measurement, and accepted-setup binding evidence.',
            currentVerifierRule:
                'Absent compact VSS public material may remain optional, incomplete compact public material must refuse as incomplete, and complete compact public material must refuse before interpolation or target-result acceptance.',
            requiredReplacementEvidence: [
                'a binding theorem for the active digit-encoded VSS message space',
                'a reviewed extractor or opening argument covering coefficient, recipient-share, aggregate, same-secret bridge, and target-smudging commitments',
                'binding review rows whose witness-difference bounds satisfy the estimator or proof preconditions used by the review',
                'hiding review rows for the final public sample count, opening distribution, correlated openings, corrupted-recipient leakage model, and multi-opening loss',
                'accepted-setup verification that recomputes the replacement binding from source constants before any positive compact-material acceptance',
                'updated compact measurement that reports public commitment-body bytes, proof-material bytes, generation time, and verification time for the replacement profile',
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
