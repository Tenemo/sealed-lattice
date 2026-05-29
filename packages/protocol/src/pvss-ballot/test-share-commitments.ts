import {
    canonicalJson,
    deriveProtocolHash,
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
const protocolHashPattern = /^[0-9a-f]{128}$/u;

type PvssBallotHashContext = Pick<
    PvssBallotAlgebraInput,
    | 'ceremonyId'
    | 'duplicateBallotPolicyHash'
    | 'electionManifestHash'
    | 'pollSpecHash'
    | 'rosterHash'
    | 'thresholdProfileHash'
    | 'voterIdentity'
    | 'voterRosterPosition'
>;

const deriveFieldElementFromHash = (HASHHex: string): FieldElement =>
    Number(BigInt(`0x${HASHHex}`) % BigInt(fieldModulus));

const deriveOpeningFieldElement = (
    context: PvssBallotAlgebraInput,
    receiverShareVector: ReceiverShareVector,
    fieldIndex: number,
): FieldElement =>
    deriveFieldElementFromHash(
        hash512Hex(openingDerivationDomain, [
            textEncoder.encode(
                canonicalJson({
                    ceremonyId: context.ceremonyId,
                    duplicateBallotPolicyHash:
                        context.duplicateBallotPolicyHash,
                    electionManifestHash: context.electionManifestHash,
                    fieldIndex,
                    fixtureEntropy: context.fixtureEntropy,
                    pollSpecHash: context.pollSpecHash,
                    receiverIdentity: receiverShareVector.receiverIdentity,
                    receiverRosterPosition:
                        receiverShareVector.receiverRosterPosition,
                    rosterHash: context.rosterHash,
                    thresholdProfileHash: context.thresholdProfileHash,
                    voterIdentity: context.voterIdentity,
                    voterRosterPosition: context.voterRosterPosition,
                }),
            ),
        ]),
    );

export const deriveTestShareCommitmentHash = (input: {
    readonly commitment: Omit<TestShareCommitment, 'shareCommitmentHash'>;
    readonly context: PvssBallotHashContext;
    readonly ballotPolynomialSetHash: string;
}): string =>
    deriveProtocolHash('ShareCommitmentHash', {
        ballotPolynomialSetHash: input.ballotPolynomialSetHash,
        ceremonyId: input.context.ceremonyId,
        commitmentValues: input.commitment.commitmentValues,
        duplicateBallotPolicyHash: input.context.duplicateBallotPolicyHash,
        electionManifestHash: input.context.electionManifestHash,
        objectType: input.commitment.objectType,
        pollSpecHash: input.context.pollSpecHash,
        rosterHash: input.context.rosterHash,
        thresholdProfileHash: input.context.thresholdProfileHash,
        receiverIdentity: input.commitment.receiverIdentity,
        receiverRosterPosition: input.commitment.receiverRosterPosition,
        voterIdentity: input.context.voterIdentity,
        voterRosterPosition: input.context.voterRosterPosition,
    });

export const deriveTestReceiverShareOpeningPayloadHash = (input: {
    readonly context: PvssBallotHashContext;
    readonly payload: Omit<TestReceiverShareOpeningPayload, 'payloadHash'>;
}): string =>
    deriveProtocolHash('ChallengeDomainHash', {
        ceremonyId: input.context.ceremonyId,
        duplicateBallotPolicyHash: input.context.duplicateBallotPolicyHash,
        electionManifestHash: input.context.electionManifestHash,
        objectType: input.payload.objectType,
        openingVector: input.payload.openingVector,
        pollSpecHash: input.context.pollSpecHash,
        purpose: 'test-receiver-share-opening-payload-v1',
        receiverIdentity: input.payload.receiverIdentity,
        receiverRosterPosition: input.payload.receiverRosterPosition,
        rosterHash: input.context.rosterHash,
        shareVector: input.payload.shareVector,
        thresholdProfileHash: input.context.thresholdProfileHash,
        voterIdentity: input.context.voterIdentity,
        voterRosterPosition: input.context.voterRosterPosition,
    });

export const deriveTestShareCommitmentWitness = (input: {
    readonly context: PvssBallotAlgebraInput;
    readonly receiverShareVector: ReceiverShareVector;
    readonly ballotPolynomialSetHash: string;
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
    const commitmentWithoutHash = {
        objectType: 'TestShareCommitment' as const,
        receiverIdentity: input.receiverShareVector.receiverIdentity,
        receiverRosterPosition:
            input.receiverShareVector.receiverRosterPosition,
        commitmentValues,
    };
    const commitment = {
        ...commitmentWithoutHash,
        shareCommitmentHash: deriveTestShareCommitmentHash({
            commitment: commitmentWithoutHash,
            context: input.context,
            ballotPolynomialSetHash: input.ballotPolynomialSetHash,
        }),
    };
    const payloadWithoutHash = {
        objectType: 'TestReceiverShareOpeningPayload' as const,
        receiverIdentity: input.receiverShareVector.receiverIdentity,
        receiverRosterPosition:
            input.receiverShareVector.receiverRosterPosition,
        shareVector: input.receiverShareVector.shareVector,
        openingVector,
    };
    const payload = {
        ...payloadWithoutHash,
        payloadHash: deriveTestReceiverShareOpeningPayloadHash({
            context: input.context,
            payload: payloadWithoutHash,
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
        !protocolHashPattern.test(witness.commitment.shareCommitmentHash) ||
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
