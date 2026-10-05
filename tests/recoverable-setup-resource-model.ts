import {
    compileWordProverResources,
    publicCoefficientAllowance,
} from '#tests/browser-word-prover-resource-model.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { operationSeedBytes } from '#tests/operation-seed-model.js';
import { compilePublicPolynomialOperatorBuffers } from '#tests/public-polynomial-operator-resource-model.js';
import { compileRecipientKeyCensus } from '#tests/recipient-key-model.js';
import { compileOpeningShareResources } from '#tests/recoverable-opening-share-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import { proofCompilerCaps } from '#tests/wide-challenge-compiler-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';

// The bounded Rust experiment embeds its physical ring into the unchanged
// common proof domain. The full candidate uses the original ring and seed
// widths by default. Both keep the profile's existing conservative sharing
// cube, limb and carry widths; no tighter outer-role parameter is assumed.
export const compileRecoverableSeedSharingProofResources = (
    participantCount: number,
    optionCount: number,
    polynomialDegree: bigint = fixedModulusBfvInputs.polynomialDegree,
    seedBits: bigint = 8n * operationSeedBytes,
) => {
    const profile = deriveSupportedProfile(participantCount, optionCount);
    const agreement = compileCommonAgreementDegreeCensus();
    const systematicSize = BigInt(agreement.systematicSize);
    if (
        polynomialDegree < shareEncryptionParameters.encryptionSupportWeight ||
        polynomialDegree > systematicSize ||
        (polynomialDegree & (polynomialDegree - 1n)) !== 0n ||
        seedBits <= 0n ||
        seedBits > polynomialDegree
    )
        throw new RangeError('Invalid seed-sharing polynomial or seed width.');
    const { sharingCoefficientBits, limbBits, carryBits } =
        profile.shareLifting;
    const sharingDegree = profile.releaseThreshold - 1;
    const signedVariableWidths = [
        ...Array.from({ length: sharingDegree }, () => [
            limbBits,
            sharingCoefficientBits - limbBits,
        ]).flat(),
        ...Array.from({ length: participantCount }, () => [
            16,
            carryBits,
            7,
            16,
            16,
            7,
        ]).flat(),
    ];
    let wordColumns = 0;
    let narrowWordColumns = 0;
    let signedBooleanColumns = 0;
    for (const bits of signedVariableWidths) {
        wordColumns += Math.max(1, Math.floor(bits / 16));
        if (bits < 16) narrowWordColumns++;
        else signedBooleanColumns += bits % 16;
    }
    // Two sparse ephemeral indicators per recipient and one Boolean seed
    // column; the public operator reads only its first seedBits positions.
    const booleanColumns = 2 * participantCount + 1 + signedBooleanColumns;
    const columns = wordColumns + booleanColumns;
    const lookupEntries = wordColumns + narrowWordColumns;
    const layout = compileWordProofLayout(columns, lookupEntries);
    const relation = {
        wordColumns,
        booleanColumns,
        narrowWordColumns,
        lookupEntries,
        disjointPairs: participantCount,
        supportRows: 2 * participantCount,
        errorColumns: 2 * participantCount,
        affineRows:
            4n * BigInt(participantCount) * polynomialDegree +
            2n * BigInt(participantCount),
    };
    const proofEngine = compileWordProverResources({
        columns,
        lookups: lookupEntries,
        preparedAdjointBytes: 0n,
    });
    // The statement owns the common polynomial and each recipient's key and
    // two ciphertext polynomials. Reuse the existing BigInt coefficient
    // allocation allowance, not a claim about native allocator object sizes.
    const publicStatementPolynomials = 1n + 3n * BigInt(participantCount);
    const publicStatementCoefficientAllowanceBytes =
        publicStatementPolynomials *
        polynomialDegree *
        publicCoefficientAllowance;
    const recipient = compileRecipientKeyCensus();
    const coefficientBytes =
        1n + BigInt(Math.ceil(recipient.modulus.toString(2).length / 8));
    // n key adjoints, one common adjoint, one sharing basis per nonconstant
    // coefficient, and the seed prefix. The current fixed fixture has one
    // such sharing basis; larger profiles extrapolate this factorization.
    const valueColumns = participantCount + sharingDegree + 2;
    const operator = compilePublicPolynomialOperatorBuffers(
        polynomialDegree,
        coefficientBytes,
        columns,
        valueColumns,
        valueColumns,
    );
    const publicStatementPolynomialBytes =
        publicStatementPolynomials * polynomialDegree * coefficientBytes;
    return {
        participantCount,
        optionCount,
        polynomialDegree,
        seedBits,
        sharingCoefficientBits,
        limbBits,
        carryBits,
        signedVariableWidths,
        systematicSize,
        verificationDomainSize: BigInt(agreement.domainSize),
        maskDimension: BigInt(agreement.maskDimension),
        queryCount: agreement.queries,
        relation,
        layout,
        proofEngine,
        ...operator,
        publicStatementCoefficientAllowanceBytes,
        publicStatementPolynomialBytes,
        // Proof-engine planning plus operator build/query/serialization
        // buffers, resident statement and two
        // serialized statement payloads. One complete proof's size remains
        // an allocation allowance although the native case streams proofs.
        // The engine includes metadata/allocator allowances. This does not
        // bound fixture generation, verifier work or a complete setup.
        nativeProofPlanningBytes:
            proofEngine.maximumLiveBytes +
            operator.operatorBuildBufferBytes +
            operator.serializedOperatorColumnBytes +
            operator.operatorQueryBufferBytes +
            publicStatementCoefficientAllowanceBytes +
            2n * publicStatementPolynomialBytes +
            layout.maximumMultiproofBytes,
    };
};

// Only the bounded native fixture's actual allocation/serialization shape.
// Its two source records precede one opening batch; proof engines run in
// sequence. This is a planning allowance, not a complete workflow bound.
export const compileBoundedOpeningShareProofResources = () => {
    const participants = 4;
    const degree = 256n;
    const seed = compileRecoverableSeedSharingProofResources(
        participants,
        2,
        degree,
        4n,
    );
    const opening = compileOpeningShareResources(participants, degree);
    const selected = BigInt(opening.parameters.selectedCount);
    const tagBytes = proofCompilerCaps.tagBits / 8n;
    const modulusBytes = BigInt(
        Math.ceil(opening.parameters.modulus.toString(2).length / 8),
    );
    // Both fixture headers: magic, seven u32 shape operands, exact modulus.
    const shapeHeaderBytes = 4n + 7n * 4n + modulusBytes;
    const seedStatementBytes =
        shapeHeaderBytes +
        3n * tagBytes +
        2n +
        seed.publicStatementPolynomialBytes;
    // The framed selection digest binds poll/roster/runtime/ordered records.
    // The original operands are expanded locally; they are not new uploads.
    const openingStatementBytes =
        shapeHeaderBytes +
        tagBytes +
        2n +
        opening.expandedStatementPolynomialBytes;
    const retainedSourceCoefficientAllowanceBytes =
        2n *
        (1n + 3n * BigInt(participants)) *
        degree *
        publicCoefficientAllowance;
    const { residentOperatorBytes, serializedOperatorColumnBytes } = opening;
    // Positive, shifted, and the active controller's statement; the caller's
    // extra public M vectors are retained until its scope controls finish.
    const openingStatementCoefficientAllowanceBytes =
        3n * (2n + 2n * selected) * degree * publicCoefficientAllowance +
        4n * selected * degree * 16n;
    // equations() now yields one key/difference polynomial at a time.
    const derivedEquationCoefficientAllowanceBytes =
        degree * publicCoefficientAllowance;
    const secondSourceStageBytes =
        seed.nativeProofPlanningBytes +
        retainedSourceCoefficientAllowanceBytes +
        2n * seedStatementBytes;
    const openingStageBytes =
        opening.proofEngine.maximumLiveBytes +
        opening.operatorBuildBufferBytes +
        serializedOperatorColumnBytes +
        opening.operatorQueryBufferBytes +
        retainedSourceCoefficientAllowanceBytes +
        openingStatementCoefficientAllowanceBytes +
        derivedEquationCoefficientAllowanceBytes +
        3n * openingStatementBytes +
        2n * seedStatementBytes +
        opening.layout.maximumMultiproofBytes;
    return {
        seed,
        opening,
        seedStatementBytes,
        openingStatementBytes,
        retainedSourceCoefficientAllowanceBytes,
        residentOperatorBytes,
        serializedOperatorColumnBytes,
        openingStatementCoefficientAllowanceBytes,
        derivedEquationCoefficientAllowanceBytes,
        secondSourceStageBytes,
        openingStageBytes,
        nativeProofPlanningBytes:
            secondSourceStageBytes > openingStageBytes
                ? secondSourceStageBytes
                : openingStageBytes,
        // One new outer proof, one opening positive, one fresh false opening,
        // and their exact statements. Copied input artifacts are separate.
        maximumNewArtifactBytes:
            seed.layout.maximumMultiproofBytes +
            2n * opening.layout.maximumMultiproofBytes +
            seedStatementBytes +
            2n * openingStatementBytes,
    };
};

// The standalone screen streams public recipes, not decoded Statements,
// witnesses or proofs. These are its actual fixed shapes, not a full-profile
// preparation plan; the normal proof wrappers remain at their bounded ring.
export const compilePublicOperatorScreenResources = (
    kind: 'seed' | 'opening',
) => {
    if (kind !== 'seed' && kind !== 'opening')
        throw new RangeError('Unknown public operator screen.');
    const agreement = compileCommonAgreementDegreeCensus();
    const degree = BigInt(agreement.systematicSize);
    const seedBits = 8n * operationSeedBytes;
    const seed = compileRecoverableSeedSharingProofResources(
        4,
        2,
        degree,
        seedBits,
    );
    const opening = compileOpeningShareResources(4, degree);
    const selected = kind === 'seed' ? seed : opening;
    const columns =
        kind === 'seed'
            ? seed.relation.wordColumns + seed.relation.booleanColumns
            : opening.wordColumns + opening.booleanColumns;
    const words =
        kind === 'seed' ? seed.relation.wordColumns : opening.wordColumns;
    const queryHalfCount = agreement.queries;
    const queryCount = 2 * queryHalfCount;
    const half = agreement.domainSize / 2;
    const physicalDegree = Number(degree);
    const lower = new Set([
        0,
        1,
        physicalDegree - 1,
        physicalDegree,
        physicalDegree + 1,
        half - 2,
        half - 1,
    ]);
    for (
        let index = 0;
        index < queryHalfCount && lower.size < queryHalfCount;
        index++
    )
        lower.add(Math.floor((index * (half - 1)) / (queryHalfCount - 1)));
    for (let index = 0; index < half && lower.size < queryHalfCount; index++)
        lower.add(index);
    const lowerIndices = [...lower].sort((left, right) => left - right);
    const queries = [
        ...lowerIndices,
        ...lowerIndices.map((index) => index + half),
    ];
    // Independent inventory of the fixed report's selected variable families.
    const physicalPairs: [number, number][] =
        kind === 'seed'
            ? [
                  [0, 0],
                  [5, physicalDegree - 1],
                  [6, physicalDegree / 2],
                  ...[
                      0,
                      physicalDegree / 4 - 1,
                      physicalDegree / 2,
                      physicalDegree - 1,
                  ].flatMap((row, recipient): [number, number][] => [
                      [35 + 2 * recipient, row],
                      [36 + 2 * recipient, physicalDegree - 1 - row],
                  ]),
                  [7, 0],
                  [9, physicalDegree - 1],
                  [10, physicalDegree / 4],
                  ...[
                      0,
                      Number(seedBits) - 1,
                      Number(seedBits),
                      physicalDegree - 1,
                  ].map((row): [number, number] => [43, row]),
              ]
            : [
                  [9, 0],
                  [9, physicalDegree / 2 - 1],
                  [9, physicalDegree - 1],
                  [10, 1],
                  [10, physicalDegree / 2],
                  [10, physicalDegree - 2],
                  [0, 0],
                  [1, physicalDegree - 1],
                  [2, physicalDegree / 2],
                  [11, physicalDegree / 4],
                  [12, physicalDegree - 1],
              ];
    const queryPairs = [
        [0, 0],
        [0, queryHalfCount - 1],
        [columns - 1, queryHalfCount],
        [columns - 1, queryCount - 1],
        [words, 1],
        [words, queryHalfCount / 2],
        [words + 1, queryHalfCount + 1],
        [words + 1, queryHalfCount + queryHalfCount / 2],
    ];
    const physicalSamples = physicalPairs.map(([column, index]) => ({
        column,
        index,
    }));
    const querySamples = queryPairs.map(([column, position]) => ({
        column,
        index: queries[position],
    }));
    const extension =
        compileSmallLimbProofFieldCensus().packedExtensionElementByteLength;
    const tags = proofCompilerCaps.tagBits / 8n;
    const reportHeaderBytes =
        4n + 8n * 4n + 3n * extension + 2n * tags + 2n * 4n;
    const sampleBytes = 2n * 4n + extension;
    const reportBytes =
        reportHeaderBytes +
        BigInt(physicalSamples.length + querySamples.length) * sampleBytes;
    const outputCapacity =
        reportHeaderBytes + BigInt(3 + 8 + 3 + 4 + 8) * sampleBytes;
    const queryIndicesBytes = BigInt(queryCount) * 4n;
    const referenceColumnBytes = degree * extension;
    const referenceQueryBytes = BigInt(queryCount) * extension;
    const stages = [
        {
            stage: 'canonical polynomial streams',
            bytes: selected.operatorBuildBufferBytes + queryIndicesBytes,
        },
        {
            stage: 'one-column query reference',
            bytes:
                selected.residentOperatorBytes +
                referenceColumnBytes +
                selected.queryTemporaryBytes +
                referenceQueryBytes +
                queryIndicesBytes,
        },
        {
            stage: 'factored query evaluation',
            bytes: selected.operatorQueryBufferBytes,
        },
        {
            stage: 'report encoding',
            bytes: BigInt(columns) * referenceQueryBytes + reportBytes,
        },
    ];
    const maximumBufferBytes = stages.reduce(
        (maximum, value) => (value.bytes > maximum ? value.bytes : maximum),
        0n,
    );
    const metadataAndAllocatorAllowance =
        selected.proofEngine.metadataAndAllocatorAllowance;
    return {
        kind,
        caseId: kind === 'seed' ? 0 : 1,
        degree,
        participants: 4,
        threshold: 2,
        selectedCount: 2,
        seedBits,
        columns,
        queryCount,
        alpha: [13n, 17n, 19n] as const,
        queries,
        physicalSamples,
        querySamples,
        reportHeaderBytes,
        sampleBytes,
        reportBytes,
        outputCapacity,
        polynomialCount: kind === 'seed' ? 1 + 3 * 4 : 2 * (2 + 1),
        maximumInputChunkBytes: selected.operatorEncodingChunkBytes,
        residentOperatorBytes: selected.residentOperatorBytes,
        stages,
        maximumBufferBytes,
        metadataAndAllocatorAllowance,
        planningBytes: maximumBufferBytes + metadataAndAllocatorAllowance,
    };
};

// Resource screen for the candidate's fixed eligible pool and selected set.
// Existing contribution-body maxima bound only the unchanged inner format.
// The additional ciphertext subtotal uses the two registered-recipient-ring
// polynomials U_i and V_i per recipient, with that ring's existing encoding.
// Outer and public opening-share proof layouts are counted separately.
// Sealed-body framing and padding-length fields, signatures, broadcast, storage,
// transfers and runtime work are not counted in the byte subtotals. No
// subtotal bounds a complete candidate package or establishes feasibility.
export const compileRecoverableSetupResourceScreen = (
    participantCount: number,
    optionCount: number,
) => {
    const profile = deriveSupportedProfile(participantCount, optionCount);
    const body = compileContributionBodyCensus(profile);
    const outerProof = compileRecoverableSeedSharingProofResources(
        participantCount,
        optionCount,
    );
    const recipient = compileRecipientKeyCensus();
    const maximumFaultCount = Math.floor((participantCount - 1) / 3);
    const selectedContributorCount = Math.max(maximumFaultCount + 1, 2);
    const eligibleContributorCount =
        selectedContributorCount + maximumFaultCount;
    const seedShareCoefficientBytes =
        1n + BigInt(Math.ceil(recipient.modulus.toString(2).length / 8));
    const seedShareCiphertextBytes =
        2n * recipient.degree * seedShareCoefficientBytes;
    const seedShareCiphertextsPerOffer = BigInt(participantCount);
    const eligibleSeedShareCiphertextCount =
        BigInt(eligibleContributorCount) * seedShareCiphertextsPerOffer;
    const selectedSeedShareCiphertextCount =
        BigInt(selectedContributorCount) * seedShareCiphertextsPerOffer;
    const maximumEligibleInnerBodyCorpusBytes =
        BigInt(eligibleContributorCount) * body.maximumBodyBytes;
    const maximumSelectedInnerBodyCorpusBytes =
        BigInt(selectedContributorCount) * body.maximumBodyBytes;
    const eligibleSeedShareCiphertextBytes =
        eligibleSeedShareCiphertextCount * seedShareCiphertextBytes;
    const selectedSeedShareCiphertextBytes =
        selectedSeedShareCiphertextCount * seedShareCiphertextBytes;
    const openingProof = compileOpeningShareResources(
        participantCount,
        recipient.degree,
    );
    const maximumOpeningBatchPayloadBytes =
        openingProof.publicShareBytes +
        openingProof.layout.maximumMultiproofBytes;
    const maximumAllOpeningBatchPayloadBytes =
        BigInt(participantCount) * maximumOpeningBatchPayloadBytes;
    const maximumEligibleBodyCiphertextAndOuterProofBytes =
        maximumEligibleInnerBodyCorpusBytes +
        eligibleSeedShareCiphertextBytes +
        BigInt(eligibleContributorCount) *
            outerProof.layout.maximumMultiproofBytes;
    return {
        participantCount,
        optionCount,
        maximumFaultCount,
        eligibleContributorCount,
        selectedContributorCount,
        echoThreshold: participantCount - maximumFaultCount,
        readyRelayThreshold: maximumFaultCount + 1,
        readyDeliveryThreshold: 2 * maximumFaultCount + 1,
        maximumInnerBodyBytes: body.maximumBodyBytes,
        maximumEligibleInnerBodyCorpusBytes,
        maximumSelectedInnerBodyCorpusBytes,
        seedSharePolynomialDegree: recipient.degree,
        seedShareCoefficientBytes,
        seedShareCiphertextBytes,
        seedShareCiphertextsPerOffer,
        eligibleSeedShareCiphertextCount,
        selectedSeedShareCiphertextCount,
        eligibleSeedShareCiphertextBytes,
        selectedSeedShareCiphertextBytes,
        maximumEligibleBodyAndSeedCiphertextBytes:
            maximumEligibleInnerBodyCorpusBytes +
            eligibleSeedShareCiphertextBytes,
        maximumSelectedBodyAndSeedCiphertextBytes:
            maximumSelectedInnerBodyCorpusBytes +
            selectedSeedShareCiphertextBytes,
        outerProof,
        maximumEligibleOuterProofBytes:
            BigInt(eligibleContributorCount) *
            outerProof.layout.maximumMultiproofBytes,
        maximumSelectedOuterProofBytes:
            BigInt(selectedContributorCount) *
            outerProof.layout.maximumMultiproofBytes,
        maximumEligibleBodyCiphertextAndOuterProofBytes,
        openingProof,
        maximumOpeningBatchPayloadBytes,
        maximumAllOpeningBatchPayloadBytes,
        maximumThresholdOpeningBatchPayloadBytes:
            BigInt(selectedContributorCount) * maximumOpeningBatchPayloadBytes,
        maximumPreparationPayloadSubtotalBytes:
            maximumEligibleBodyCiphertextAndOuterProofBytes +
            maximumAllOpeningBatchPayloadBytes,
    };
};
