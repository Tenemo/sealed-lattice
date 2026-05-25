import {
    aggregateDerivationProofEncodingProfileId,
    aggregateDerivationProofParameterProfileId,
    aggregateDerivationProofProfileId,
    type AggregateDerivationComponent,
    type AggregateDerivationPackageReference,
    type AggregateDerivationStatement,
    type AggregateDerivationVerification,
    type AggregateShareCommitment,
    type ProtocolDigest,
    type RefusalRecord,
} from '@sealed-lattice/types';

import { deriveProofBytesDigest } from '../objects.js';
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
    forbiddenPublicWitnessFieldNames,
    lowercaseHexBytesPattern,
    protocolDigestPattern,
} from './constants.js';
import {
    deriveAggregateCommitmentBodyDigest,
    deriveAggregateDerivationComponentDigest,
    deriveAggregateDerivationProofRecordDigest,
    deriveAggregateDerivationStatementDigest,
    deriveAggregateShareCommitmentDigest,
} from './digests.js';

const packageReferencesAreCanonical = (
    packageReferences: readonly AggregateDerivationPackageReference[],
): boolean => {
    const seenPackageDigests = new Set<ProtocolDigest>();
    let previousPackageDigest: ProtocolDigest | undefined;

    for (const packageReference of packageReferences) {
        if (seenPackageDigests.has(packageReference.ballotPackageDigest)) {
            return false;
        }
        if (
            previousPackageDigest !== undefined &&
            previousPackageDigest.localeCompare(
                packageReference.ballotPackageDigest,
            ) > 0
        ) {
            return false;
        }
        previousPackageDigest = packageReference.ballotPackageDigest;
        seenPackageDigests.add(packageReference.ballotPackageDigest);
    }

    return true;
};

const collectForbiddenWitnessFieldRefusals = (
    value: unknown,
    objectDigest: ProtocolDigest | undefined,
    path: string,
): readonly RefusalRecord[] => {
    if (Array.isArray(value)) {
        return value.flatMap((item, itemIndex) =>
            collectForbiddenWitnessFieldRefusals(
                item,
                objectDigest,
                `${path}[${itemIndex}]`,
            ),
        );
    }
    if (typeof value !== 'object' || value === null) {
        return [];
    }

    const refusedObjects: RefusalRecord[] = [];
    for (const [fieldName, fieldValue] of Object.entries(value)) {
        if (forbiddenPublicWitnessFieldNames.has(fieldName)) {
            refusedObjects.push(
                createAggregateRefusal(
                    `Aggregate derivation public component must not expose witness field ${path}.${fieldName}.`,
                    objectDigest,
                ),
            );
            continue;
        }
        refusedObjects.push(
            ...collectForbiddenWitnessFieldRefusals(
                fieldValue,
                objectDigest,
                `${path}.${fieldName}`,
            ),
        );
    }

    return refusedObjects;
};

const collectAggregateStatementRefusals = (
    statement: AggregateDerivationStatement,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const { aggregateDerivationStatementDigest, ...statementWithoutDigest } =
        statement;
    const expectedStatementDigest = deriveAggregateDerivationStatementDigest(
        statementWithoutDigest,
    );
    refusedObjects.push(
        ...collectBallotPrivacyDimensionRefusals({
            objectDigest: aggregateDerivationStatementDigest,
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
        statement.aggregateDerivationStatementDigest !==
            expectedStatementDigest ||
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
                'Aggregate derivation statement digest or shape is invalid.',
                aggregateDerivationStatementDigest,
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
    const expectedBodyDigest = deriveAggregateCommitmentBodyDigest({
        commitmentPolynomialVector:
            input.aggregateCommitment.commitmentPolynomialVector,
        shareCommitmentProfileDigest:
            input.aggregateCommitment.shareCommitmentProfileDigest,
    });
    const {
        aggregateShareCommitmentDigest,
        ...aggregateCommitmentWithoutDigest
    } = input.aggregateCommitment;
    void aggregateShareCommitmentDigest;
    const expectedCommitmentDigest = deriveAggregateShareCommitmentDigest(
        aggregateCommitmentWithoutDigest,
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
        input.aggregateCommitment.aggregateShareCommitmentDigest !==
            expectedCommitmentDigest ||
        input.aggregateCommitment.commitmentBodyDigest !== expectedBodyDigest ||
        input.aggregateCommitment.aggregateShareCommitmentDigest !==
            input.statement.aggregateShareCommitmentDigest ||
        input.aggregateCommitment.ballotSetDigest !==
            input.statement.ballotSetDigest ||
        input.aggregateCommitment.ceremonyId !== input.statement.ceremonyId ||
        input.aggregateCommitment.manifestDigest !==
            input.statement.manifestDigest ||
        input.aggregateCommitment.rosterDigest !==
            input.statement.rosterDigest ||
        input.aggregateCommitment.pollSpecDigest !==
            input.statement.pollSpecDigest ||
        input.aggregateCommitment.contributorIdentity !==
            input.statement.contributorIdentity ||
        input.aggregateCommitment.contributorRosterPosition !==
            input.statement.contributorRosterPosition ||
        input.aggregateCommitment.shareCommitmentProfileDigest !==
            input.statement.shareCommitmentProfileDigest ||
        input.aggregateCommitment.shareVectorWidth !==
            input.statement.shareVectorWidth ||
        !vectorShapeIsValid
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate share commitment digest, context, or polynomial shape is invalid.',
                input.aggregateCommitment.aggregateShareCommitmentDigest,
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
    const {
        aggregateDerivationProofRecordDigest,
        ...proofRecordWithoutDigest
    } = proofRecord;
    void aggregateDerivationProofRecordDigest;
    const proofBytesDigest = lowercaseHexBytesPattern.test(
        proofInput.proofBytesHex,
    )
        ? deriveProofBytesDigest({ proofBytesHex: proofInput.proofBytesHex })
        : undefined;
    const expectedProofRecordDigest =
        deriveAggregateDerivationProofRecordDigest(proofRecordWithoutDigest);

    if (
        proofRecord.objectType !== 'AggregateDerivationProofRecord' ||
        proofRecord.objectVersion !== 1 ||
        proofRecord.aggregateDerivationProofRecordDigest !==
            expectedProofRecordDigest ||
        proofRecord.aggregateDerivationStatementDigest !==
            component.statement.aggregateDerivationStatementDigest ||
        proofRecord.aggregateShareCommitmentDigest !==
            component.aggregateCommitment.aggregateShareCommitmentDigest ||
        proofRecord.componentId !== aggregateDerivationComponentId ||
        proofInput.componentId !== aggregateDerivationComponentId ||
        proofInput.proofStatementFormat !==
            'sparse-polynomial-matrix-linear-proof-v1' ||
        proofInput.statementDigest !==
            component.statement.aggregateDerivationStatementDigest ||
        proofInput.componentProofStatementDigest !==
            proofRecord.componentProofStatementDigest ||
        proofBytesDigest === undefined ||
        proofRecord.proofBytesDigest !== proofBytesDigest ||
        proofRecord.proofSizeBytes !== proofInput.proofBytesHex.length / 2 ||
        !protocolDigestPattern.test(proofRecord.proofRoot)
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate derivation proof record or proof input is invalid.',
                proofRecord.aggregateDerivationProofRecordDigest,
            ),
        );
    }

    return refusedObjects;
};

export const verifyAggregateDerivationComponentStructure = (
    component: AggregateDerivationComponent,
): AggregateDerivationVerification => {
    const componentDigest = component.aggregateDerivationComponentDigest;
    const certificateVerification = verifyShareCommitmentMessageBoundCert({
        certificate: component.shareCommitmentMessageBoundCert,
        expectedShareCommitmentProfileDigest:
            component.statement.shareCommitmentProfileDigest,
    });
    const refusedObjects: RefusalRecord[] = [
        ...collectForbiddenWitnessFieldRefusals(
            component,
            componentDigest,
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
            .shareCommitmentMessageBoundCertDigest !==
            component.statement.shareCommitmentMessageBoundCertDigest ||
        component.shareCommitmentMessageBoundCert.maximumCanonicalTurnout <
            component.statement.canonicalTurnout ||
        component.shareCommitmentMessageBoundCert.maximumCanonicalTurnout >
            ballotPrivacyMaximumParticipantCount
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate derivation no-wraparound certificate is not bound to the statement.',
                component.statement.shareCommitmentMessageBoundCertDigest,
            ),
        );
    }

    const { aggregateDerivationComponentDigest, ...componentWithoutDigest } =
        component;
    if (
        aggregateDerivationComponentDigest !==
        deriveAggregateDerivationComponentDigest(componentWithoutDigest)
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate derivation component digest does not match its canonical payload.',
                componentDigest,
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
            acceptedDigests: [],
            aggregateDerivationComponentDigest: componentDigest,
            backendAvailable: false,
            refusedObjects,
            statusLabels: unsafeSmallRosterStatusLabels,
            unresolvedReason: refusedObjects[0]?.code ?? 'BallotPackageInvalid',
        };
    }

    return {
        ok: true,
        acceptedDigests: [
            component.aggregateCommitment.aggregateShareCommitmentDigest,
            component.proofRecord.aggregateDerivationProofRecordDigest,
            componentDigest,
        ],
        aggregateDerivationComponentDigest: componentDigest,
        backendAvailable: false,
        refusedObjects: [],
        statusLabels: ['pending', ...unsafeSmallRosterStatusLabels],
        unresolvedReason: null,
    };
};
