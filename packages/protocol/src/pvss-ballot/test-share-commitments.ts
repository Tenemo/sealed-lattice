import {
    canonicalJson,
    deriveProtocolDigest,
    hash512Hex,
} from '@sealed-lattice/crypto';
import type {
    FieldElement,
    PvssBallotAlgebraInput,
    ReceiverShareVector,
    TestReceiverShareOpeningPayload,
    TestShareCommitment,
    TestShareCommitmentWitness,
} from '@sealed-lattice/types';

import {
    addFieldElements,
    assertCanonicalFieldElement,
    fieldModulus,
    normalizeFieldElement,
} from '../plaintext-oracle/field.js';

import { pvssBallotShareVectorWidth } from './common.js';
import { assertCanonicalReceiverShareVector } from './receiver-shares.js';

const textEncoder = new TextEncoder();
const openingDerivationDomain =
    'sealed-lattice-internal/pvss-ballot-fixture-opening-v1';
const protocolDigestPattern = /^[0-9a-f]{128}$/u;

type PvssBallotDigestContext = Pick<
    PvssBallotAlgebraInput,
    | 'ceremonyId'
    | 'duplicateBallotPolicyDigest'
    | 'electionManifestDigest'
    | 'pollSpecDigest'
    | 'rosterDigest'
    | 'thresholdProfileDigest'
    | 'voterIdentity'
    | 'voterRosterPosition'
>;

const deriveFieldElementFromDigest = (digestHex: string): FieldElement =>
    Number(BigInt(`0x${digestHex}`) % BigInt(fieldModulus));

const deriveOpeningFieldElement = (
    context: PvssBallotAlgebraInput,
    receiverShareVector: ReceiverShareVector,
    fieldIndex: number,
): FieldElement =>
    deriveFieldElementFromDigest(
        hash512Hex(openingDerivationDomain, [
            textEncoder.encode(
                canonicalJson({
                    ceremonyId: context.ceremonyId,
                    duplicateBallotPolicyDigest:
                        context.duplicateBallotPolicyDigest,
                    electionManifestDigest: context.electionManifestDigest,
                    fieldIndex,
                    fixtureEntropy: context.fixtureEntropy,
                    pollSpecDigest: context.pollSpecDigest,
                    receiverIdentity: receiverShareVector.receiverIdentity,
                    receiverRosterPosition:
                        receiverShareVector.receiverRosterPosition,
                    rosterDigest: context.rosterDigest,
                    thresholdProfileDigest: context.thresholdProfileDigest,
                    voterIdentity: context.voterIdentity,
                    voterRosterPosition: context.voterRosterPosition,
                }),
            ),
        ]),
    );

export const deriveTestShareCommitmentDigest = (input: {
    readonly commitment: Omit<TestShareCommitment, 'shareCommitmentDigest'>;
    readonly context: PvssBallotDigestContext;
    readonly ballotPolynomialSetDigest: string;
}): string =>
    deriveProtocolDigest('ShareCommitmentDigest', {
        ballotPolynomialSetDigest: input.ballotPolynomialSetDigest,
        ceremonyId: input.context.ceremonyId,
        commitmentValues: input.commitment.commitmentValues,
        duplicateBallotPolicyDigest: input.context.duplicateBallotPolicyDigest,
        electionManifestDigest: input.context.electionManifestDigest,
        objectType: input.commitment.objectType,
        pollSpecDigest: input.context.pollSpecDigest,
        rosterDigest: input.context.rosterDigest,
        thresholdProfileDigest: input.context.thresholdProfileDigest,
        receiverIdentity: input.commitment.receiverIdentity,
        receiverRosterPosition: input.commitment.receiverRosterPosition,
        voterIdentity: input.context.voterIdentity,
        voterRosterPosition: input.context.voterRosterPosition,
    });

export const deriveTestReceiverShareOpeningPayloadDigest = (input: {
    readonly context: PvssBallotDigestContext;
    readonly payload: Omit<TestReceiverShareOpeningPayload, 'payloadDigest'>;
}): string =>
    deriveProtocolDigest('TestReceiverShareOpeningPayloadDigest', {
        ceremonyId: input.context.ceremonyId,
        duplicateBallotPolicyDigest: input.context.duplicateBallotPolicyDigest,
        electionManifestDigest: input.context.electionManifestDigest,
        objectType: input.payload.objectType,
        openingVector: input.payload.openingVector,
        pollSpecDigest: input.context.pollSpecDigest,
        receiverIdentity: input.payload.receiverIdentity,
        receiverRosterPosition: input.payload.receiverRosterPosition,
        rosterDigest: input.context.rosterDigest,
        shareVector: input.payload.shareVector,
        thresholdProfileDigest: input.context.thresholdProfileDigest,
        voterIdentity: input.context.voterIdentity,
        voterRosterPosition: input.context.voterRosterPosition,
    });

export const deriveTestShareCommitmentWitness = (input: {
    readonly context: PvssBallotAlgebraInput;
    readonly receiverShareVector: ReceiverShareVector;
    readonly ballotPolynomialSetDigest: string;
}): {
    readonly payload: TestReceiverShareOpeningPayload;
    readonly witness: TestShareCommitmentWitness;
} => {
    assertCanonicalReceiverShareVector(input.receiverShareVector);

    const openingVector = Array.from(
        { length: pvssBallotShareVectorWidth },
        (_unused, fieldIndex) =>
            deriveOpeningFieldElement(
                input.context,
                input.receiverShareVector,
                fieldIndex,
            ),
    );
    const commitmentValues = input.receiverShareVector.shareVector.map(
        (fieldElement, fieldIndex) =>
            addFieldElements(fieldElement, openingVector[fieldIndex] ?? 0),
    );
    const commitmentWithoutDigest = {
        objectType: 'TestShareCommitment' as const,
        receiverIdentity: input.receiverShareVector.receiverIdentity,
        receiverRosterPosition:
            input.receiverShareVector.receiverRosterPosition,
        commitmentValues,
    };
    const commitment = {
        ...commitmentWithoutDigest,
        shareCommitmentDigest: deriveTestShareCommitmentDigest({
            commitment: commitmentWithoutDigest,
            context: input.context,
            ballotPolynomialSetDigest: input.ballotPolynomialSetDigest,
        }),
    };
    const payloadWithoutDigest = {
        objectType: 'TestReceiverShareOpeningPayload' as const,
        receiverIdentity: input.receiverShareVector.receiverIdentity,
        receiverRosterPosition:
            input.receiverShareVector.receiverRosterPosition,
        shareVector: input.receiverShareVector.shareVector,
        openingVector,
    };
    const payload = {
        ...payloadWithoutDigest,
        payloadDigest: deriveTestReceiverShareOpeningPayloadDigest({
            context: input.context,
            payload: payloadWithoutDigest,
        }),
    };

    return {
        payload,
        witness: {
            commitment,
            openingVector,
            shareVector: input.receiverShareVector.shareVector,
        },
    };
};

export const verifyTestShareCommitmentOpening = (
    witness: TestShareCommitmentWitness,
): boolean => {
    if (
        witness.commitment.objectType !== 'TestShareCommitment' ||
        !protocolDigestPattern.test(witness.commitment.shareCommitmentDigest) ||
        witness.openingVector.length !== pvssBallotShareVectorWidth ||
        witness.shareVector.length !== pvssBallotShareVectorWidth ||
        witness.commitment.commitmentValues.length !==
            pvssBallotShareVectorWidth
    ) {
        return false;
    }

    try {
        return witness.shareVector.every((fieldElement, fieldIndex) => {
            assertCanonicalFieldElement(
                fieldElement,
                `test share field ${String(fieldIndex)}`,
            );
            assertCanonicalFieldElement(
                witness.openingVector[fieldIndex] ?? 0,
                `test opening field ${String(fieldIndex)}`,
            );
            assertCanonicalFieldElement(
                witness.commitment.commitmentValues[fieldIndex] ?? 0,
                `test commitment field ${String(fieldIndex)}`,
            );

            return (
                addFieldElements(
                    fieldElement,
                    normalizeFieldElement(
                        witness.openingVector[fieldIndex] ?? 0,
                    ),
                ) === witness.commitment.commitmentValues[fieldIndex]
            );
        });
    } catch {
        return false;
    }
};
