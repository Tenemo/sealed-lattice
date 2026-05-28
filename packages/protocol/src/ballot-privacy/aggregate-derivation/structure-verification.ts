import {
    aggregateDerivationProofEncodingProfileId,
    aggregateDerivationProofParameterProfileId,
    aggregateDerivationProofProfileId,
    type AggregateDerivationComponent,
    type AggregateDerivationPackageReference,
    type AggregateDerivationStatement,
    type AggregateDerivationVerification,
    type AggregateShareCommitment,
    type ProtocolHash,
    type RefusalRecord,
} from '@sealed-lattice/types';

import { deriveProofBytesHash } from '../objects.js';
import { verifyShareCommitmentMessageBoundCert } from '../profiles.js';
import {
    ballotPrivacyMaximumParticipantCount,
    ballotPrivacyMinimumSafeParticipantCount,
    getBallotPrivacyEncodedShareVectorWidth,
    shareCommitmentModuleDegree,
    shareCommitmentModuleRank,
    shareCommitmentModulus,
} from '../protocol-parameters.js';
import {
    ballotPrivacyMinimumUnsafeParticipantCount,
    collectBallotPrivacyDimensionRefusals,
} from '../supported-dimensions.js';

import {
    aggregateDerivationComponentId,
    createAggregateRefusal,
    lowercaseHexBytesPattern,
    protocolHashPattern,
} from './constants.js';
import {
    deriveAggregateCommitmentBodyHash,
    deriveAggregateDerivationComponentHash,
    deriveAggregateDerivationProofRecordHash,
    deriveAggregateDerivationStatementHash,
    deriveAggregateShareCommitmentHash,
} from './hashes.js';
import { collectForbiddenWitnessFieldRefusals as collectBoundedForbiddenWitnessFieldRefusals } from './witness-field-refusals.js';

const packageReferencesAreCanonical = (
    packageReferences: readonly AggregateDerivationPackageReference[],
): boolean => {
    const seenPackageHashes = new Set<ProtocolHash>();
    let previousPackageHash: ProtocolHash | undefined;

    for (const packageReference of packageReferences) {
        if (seenPackageHashes.has(packageReference.ballotPackageHash)) {
            return false;
        }
        if (
            previousPackageHash !== undefined &&
            previousPackageHash.localeCompare(
                packageReference.ballotPackageHash,
            ) > 0
        ) {
            return false;
        }
        previousPackageHash = packageReference.ballotPackageHash;
        seenPackageHashes.add(packageReference.ballotPackageHash);
    }

    return true;
};

const collectForbiddenWitnessFieldRefusals = (
    value: unknown,
    objectHash: ProtocolHash | undefined,
    path: string,
): readonly RefusalRecord[] =>
    collectBoundedForbiddenWitnessFieldRefusals(value, objectHash, path, {
        publicObjectDescription: 'Aggregate derivation public component',
    });

const collectAggregateStatementRefusals = (
    statement: AggregateDerivationStatement,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const { aggregateDerivationStatementHash, ...statementWithoutHash } =
        statement;
    const expectedStatementHash =
        deriveAggregateDerivationStatementHash(statementWithoutHash);
    refusedObjects.push(
        ...collectBallotPrivacyDimensionRefusals({
            objectHash: aggregateDerivationStatementHash,
            optionCount: statement.optionCount,
            participantCount: statement.participantCount,
            shareVectorWidth: statement.shareVectorWidth,
            unsafeSmallRosterAcknowledged:
                statement.unsafeSmallRosterAcknowledged === true,
        }),
    );
    const smallRosterAcknowledgementMatchesPolicy =
        statement.participantCount < ballotPrivacyMinimumSafeParticipantCount
            ? statement.unsafeSmallRosterAcknowledged === true
            : statement.unsafeSmallRosterAcknowledged !== true;
    if (
        statement.objectType !== 'AggregateDerivationStatement' ||
        statement.objectVersion !== 1 ||
        statement.aggregateDerivationStatementHash !== expectedStatementHash ||
        statement.proofProfileId !== aggregateDerivationProofProfileId ||
        statement.proofParameterProfileId !==
            aggregateDerivationProofParameterProfileId ||
        statement.proofEncodingProfileId !==
            aggregateDerivationProofEncodingProfileId ||
        statement.shareVectorWidth !==
            getBallotPrivacyEncodedShareVectorWidth(statement.optionCount) ||
        statement.participantCount < statement.contributorRosterPosition ||
        statement.canonicalTurnout !== statement.packageReferences.length ||
        !packageReferencesAreCanonical(statement.packageReferences) ||
        !smallRosterAcknowledgementMatchesPolicy
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate derivation statement hash or shape is invalid.',
                aggregateDerivationStatementHash,
            ),
        );
    }
    return refusedObjects;
};

const collectAggregateCommitmentRefusals = (input: {
    readonly aggregateCommitment: AggregateShareCommitment;
    readonly statement: AggregateDerivationStatement;
}): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedBodyHash = deriveAggregateCommitmentBodyHash({
        commitmentPolynomialVector:
            input.aggregateCommitment.commitmentPolynomialVector,
        shareCommitmentProfileHash:
            input.aggregateCommitment.shareCommitmentProfileHash,
    });
    const { aggregateShareCommitmentHash, ...aggregateCommitmentWithoutHash } =
        input.aggregateCommitment;
    void aggregateShareCommitmentHash;
    const expectedCommitmentHash = deriveAggregateShareCommitmentHash(
        aggregateCommitmentWithoutHash,
    );
    const vectorShapeIsValid =
        input.aggregateCommitment.commitmentPolynomialVector.length ===
            shareCommitmentModuleRank &&
        input.aggregateCommitment.commitmentPolynomialVector.every(
            (polynomial) =>
                polynomial.length === shareCommitmentModuleDegree &&
                polynomial.every((entry) => {
                    try {
                        return (
                            /^(?:0|[1-9][0-9]*)$/u.test(entry) &&
                            BigInt(entry) < shareCommitmentModulus
                        );
                    } catch {
                        return false;
                    }
                }),
        );

    if (
        input.aggregateCommitment.objectType !== 'AggregateShareCommitment' ||
        input.aggregateCommitment.objectVersion !== 1 ||
        input.aggregateCommitment.aggregateShareCommitmentHash !==
            expectedCommitmentHash ||
        input.aggregateCommitment.commitmentBodyHash !== expectedBodyHash ||
        input.aggregateCommitment.aggregateShareCommitmentHash !==
            input.statement.aggregateShareCommitmentHash ||
        input.aggregateCommitment.ballotSetHash !==
            input.statement.ballotSetHash ||
        input.aggregateCommitment.ceremonyId !== input.statement.ceremonyId ||
        input.aggregateCommitment.manifestHash !==
            input.statement.manifestHash ||
        input.aggregateCommitment.rosterHash !== input.statement.rosterHash ||
        input.aggregateCommitment.pollSpecHash !==
            input.statement.pollSpecHash ||
        input.aggregateCommitment.contributorIdentity !==
            input.statement.contributorIdentity ||
        input.aggregateCommitment.contributorRosterPosition !==
            input.statement.contributorRosterPosition ||
        input.aggregateCommitment.shareCommitmentProfileHash !==
            input.statement.shareCommitmentProfileHash ||
        input.aggregateCommitment.shareVectorWidth !==
            input.statement.shareVectorWidth ||
        !vectorShapeIsValid
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate share commitment hash, context, or polynomial shape is invalid.',
                input.aggregateCommitment.aggregateShareCommitmentHash,
            ),
        );
    }

    return refusedObjects;
};

const collectProofRecordRefusals = (
    component: AggregateDerivationComponent,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const proofInput = component.proofInput;
    const proofRecord = component.proofRecord;
    const { aggregateDerivationProofRecordHash, ...proofRecordWithoutHash } =
        proofRecord;
    void aggregateDerivationProofRecordHash;
    const proofBytesHash = lowercaseHexBytesPattern.test(
        proofInput.proofBytesHex,
    )
        ? deriveProofBytesHash({ proofBytesHex: proofInput.proofBytesHex })
        : undefined;
    const expectedProofRecordHash = deriveAggregateDerivationProofRecordHash(
        proofRecordWithoutHash,
    );

    if (
        proofRecord.objectType !== 'AggregateDerivationProofRecord' ||
        proofRecord.objectVersion !== 1 ||
        proofRecord.aggregateDerivationProofRecordHash !==
            expectedProofRecordHash ||
        proofRecord.aggregateDerivationStatementHash !==
            component.statement.aggregateDerivationStatementHash ||
        proofRecord.aggregateShareCommitmentHash !==
            component.aggregateCommitment.aggregateShareCommitmentHash ||
        proofRecord.componentId !== aggregateDerivationComponentId ||
        proofInput.componentId !== aggregateDerivationComponentId ||
        proofInput.proofStatementFormat !==
            'sparse-polynomial-matrix-linear-proof-v1' ||
        proofInput.statementHash !==
            component.statement.aggregateDerivationStatementHash ||
        proofInput.componentProofStatementHash !==
            proofRecord.componentProofStatementHash ||
        proofBytesHash === undefined ||
        proofRecord.proofBytesHash !== proofBytesHash ||
        proofRecord.proofSizeBytes !== proofInput.proofBytesHex.length / 2 ||
        !protocolHashPattern.test(proofRecord.proofRoot)
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate derivation proof record or proof input is invalid.',
                proofRecord.aggregateDerivationProofRecordHash,
            ),
        );
    }

    return refusedObjects;
};

export const verifyAggregateDerivationComponentStructure = (
    component: AggregateDerivationComponent,
): AggregateDerivationVerification => {
    const componentHash = component.aggregateDerivationComponentHash;
    const certificateVerification = verifyShareCommitmentMessageBoundCert({
        certificate: component.shareCommitmentMessageBoundCert,
        expectedShareCommitmentProfileHash:
            component.statement.shareCommitmentProfileHash,
    });
    const refusedObjects: RefusalRecord[] = [
        ...collectForbiddenWitnessFieldRefusals(
            component,
            componentHash,
            'component',
        ),
        ...collectAggregateStatementRefusals(component.statement),
        ...collectAggregateCommitmentRefusals({
            aggregateCommitment: component.aggregateCommitment,
            statement: component.statement,
        }),
        ...collectProofRecordRefusals(component),
        ...certificateVerification.refusedObjects,
    ];
    if (
        component.shareCommitmentMessageBoundCert.shareVectorWidth !==
            component.statement.shareVectorWidth ||
        component.shareCommitmentMessageBoundCert
            .shareCommitmentMessageBoundCertHash !==
            component.statement.shareCommitmentMessageBoundCertHash ||
        component.shareCommitmentMessageBoundCert.maximumCanonicalTurnout <
            component.statement.canonicalTurnout ||
        component.shareCommitmentMessageBoundCert.maximumCanonicalTurnout >
            ballotPrivacyMaximumParticipantCount
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate derivation no-wraparound certificate is not bound to the statement.',
                component.statement.shareCommitmentMessageBoundCertHash,
            ),
        );
    }

    const { aggregateDerivationComponentHash, ...componentWithoutHash } =
        component;
    let expectedComponentHash: ProtocolHash | undefined;
    try {
        expectedComponentHash =
            deriveAggregateDerivationComponentHash(componentWithoutHash);
    } catch (error) {
        refusedObjects.push(
            createAggregateRefusal(
                `Aggregate derivation component hash could not be canonicalized: ${
                    error instanceof Error ? error.message : String(error)
                }.`,
                componentHash,
            ),
        );
    }
    if (
        expectedComponentHash === undefined ||
        aggregateDerivationComponentHash !== expectedComponentHash
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate derivation component hash does not match its canonical payload.',
                componentHash,
            ),
        );
    }

    const unsafeSmallRosterStatusLabels =
        component.statement.participantCount >=
            ballotPrivacyMinimumUnsafeParticipantCount &&
        component.statement.participantCount <
            ballotPrivacyMinimumSafeParticipantCount
            ? (['casualMicroRoster'] as const)
            : [];
    if (refusedObjects.length > 0) {
        return {
            ok: false,
            acceptedHashes: [],
            aggregateDerivationComponentHash: componentHash,
            backendAvailable: false,
            refusedObjects,
            statusLabels: unsafeSmallRosterStatusLabels,
            unresolvedReason: refusedObjects[0]?.code ?? 'BallotPackageInvalid',
        };
    }

    return {
        ok: true,
        acceptedHashes: [
            component.aggregateCommitment.aggregateShareCommitmentHash,
            component.proofRecord.aggregateDerivationProofRecordHash,
            componentHash,
        ],
        aggregateDerivationComponentHash: componentHash,
        backendAvailable: false,
        refusedObjects: [],
        statusLabels: ['pending', ...unsafeSmallRosterStatusLabels],
        unresolvedReason: null,
    };
};
