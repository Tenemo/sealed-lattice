import {
    compileWordProverResources,
    publicCoefficientAllowance,
} from '#tests/browser-word-prover-resource-model.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { operationSeedBytes } from '#tests/operation-seed-model.js';
import { compileOpeningShareResources } from '#tests/recoverable-opening-share-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
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
    const field = compileSmallLimbProofFieldCensus();
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
    // The bounded native operator retains one extension-field vector per
    // column. LinearOracle::create also encodes one such vector at a time.
    // Count both throughout, even at engine stages that can release them.
    const residentOperatorBytes =
        BigInt(columns) *
        polynomialDegree *
        field.packedExtensionElementByteLength;
    const serializedOperatorColumnBytes =
        polynomialDegree * field.packedExtensionElementByteLength;
    // The statement owns the common polynomial and each recipient's key and
    // two ciphertext polynomials. Reuse the existing BigInt coefficient
    // allocation allowance, not a claim about native allocator object sizes.
    const publicStatementPolynomials = 1n + 3n * BigInt(participantCount);
    const publicStatementCoefficientAllowanceBytes =
        publicStatementPolynomials *
        polynomialDegree *
        publicCoefficientAllowance;
    const recipient = compileRegistrationKeyRelationCensus();
    const coefficientBytes =
        1n + BigInt(Math.ceil(recipient.modulus.toString(2).length / 8));
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
        residentOperatorBytes,
        serializedOperatorColumnBytes,
        publicStatementCoefficientAllowanceBytes,
        publicStatementPolynomialBytes,
        // Proof-engine planning plus resident operator/statement and two
        // serialized statement payloads. One complete proof's size remains
        // an allocation allowance although the native case streams proofs.
        // The engine includes metadata/allocator allowances. This does not
        // bound fixture generation, verifier work or a complete setup.
        nativeProofPlanningBytes:
            proofEngine.maximumLiveBytes +
            residentOperatorBytes +
            serializedOperatorColumnBytes +
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
    const field = compileSmallLimbProofFieldCensus();
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
    const residentOperatorBytes =
        BigInt(opening.wordColumns + opening.booleanColumns) *
        degree *
        field.packedExtensionElementByteLength;
    const serializedOperatorColumnBytes =
        degree * field.packedExtensionElementByteLength;
    // Positive, shifted, and the active controller's statement; the caller's
    // extra public M vectors are retained until its scope controls finish.
    const openingStatementCoefficientAllowanceBytes =
        3n * (2n + 2n * selected) * degree * publicCoefficientAllowance +
        4n * selected * degree * 16n;
    const derivedEquationCoefficientAllowanceBytes =
        (1n + selected) * degree * publicCoefficientAllowance;
    const secondSourceStageBytes =
        seed.nativeProofPlanningBytes +
        retainedSourceCoefficientAllowanceBytes +
        2n * seedStatementBytes;
    const openingStageBytes =
        opening.proofEngine.maximumLiveBytes +
        residentOperatorBytes +
        serializedOperatorColumnBytes +
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
    const recipient = compileRegistrationKeyRelationCensus();
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
