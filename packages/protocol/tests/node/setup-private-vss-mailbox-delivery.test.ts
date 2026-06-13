import {
    createPrivateVssMailboxKeyPair,
    deriveProtocolHash,
    hash512Hex,
} from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import { createPrivateVssMailboxDeliverySet } from '#packages/protocol/src/index';
import {
    privateVssShareSuccinctProofModelStatus,
    privateVssShareSuccinctProofVerificationStatus,
} from '#packages/protocol/src/setup/private-vss-mailbox-delivery';

const fixtureHash = (label: string): string =>
    deriveProtocolHash('ActionContextHash', {
        fixture: 'setup-private-vss-mailbox-delivery',
        label,
    });

const setupContext = {
    ceremonyId: 'ceremony-1',
    manifestHash: fixtureHash('manifest'),
    rosterHash: fixtureHash('roster'),
    setupProfileHash: fixtureHash('setup-profile'),
    qShareHash: fixtureHash('q-share'),
    carryAwareVssShareRelationProfileHash: fixtureHash('carry-aware'),
    commitmentProfileHash: fixtureHash('commitment-profile'),
    setupEpoch: 'setup-epoch-1',
} as const;

describe('private VSS mailbox delivery', () => {
    it('refuses to build delivery envelopes without private share proof generation', async () => {
        await expect(
            createPrivateVssMailboxDeliverySet({
                kernel: {
                    deriveProtocolHash: ({ namespace, value }) =>
                        deriveProtocolHash(namespace, value),
                    verifyPrivateVssShareEnvelope: () => {
                        throw new Error(
                            'local verifier must not be reached without proof generation.',
                        );
                    },
                },
                setupContext,
                phaseOrderHash: fixtureHash('phase-order'),
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                vssCoefficientCommitmentRoot: fixtureHash(
                    'vss-coefficient-commitment',
                ),
                qSharePrimes: [65_537],
                ringDegree: 2,
                participantCount: 1,
                deliveryPhaseNumber: 6,
                verificationPhaseNumber: 7,
                sourceTrusteeContributionStates: [
                    {
                        sourceTrusteeIdentity: 'trustee-0',
                        sourceTrusteeRosterPosition: 0,
                        sourceTrusteeCommitmentRoot: fixtureHash(
                            'source-trustee-root',
                        ),
                        sourceTrusteeCoefficientCommitmentRecord: {},
                        sourceTrusteeCoefficientCommitmentMaterialRecords: [],
                        coefficientOpenings: [
                            {
                                rnsLimbIndex: 0,
                                rnsPrime: 65_537,
                                shamirCoefficientIndex: 0,
                                commitmentRoot: fixtureHash('coefficient-root'),
                                coefficientMessage: [1, 2],
                                randomnessByColumn: [[0, 1]],
                            },
                        ],
                    },
                ],
                recipients: [
                    {
                        recipientIdentity: 'trustee-0',
                        recipientRosterPosition: 0,
                        mailboxPublicKeyBytesHex: '00',
                    },
                ],
            }),
        ).rejects.toThrow(/privateVssShareProof generation/u);
    });

    it('moves private VSS proof bytes into root-bound transported material when requested', async () => {
        const proofBytesHex = '0001020304050607';
        const proofBytes = Uint8Array.from([0, 1, 2, 3, 4, 5, 6, 7]);
        const proofBytesHash = hash512Hex(
            'sealed-lattice/setup/private-vss-share/succinct-proof-bytes-v1',
            [proofBytes],
        );
        let observedPrivateEnvelope: Record<string, unknown> | undefined;
        let observedTransportedProofMaterial:
            | Record<string, unknown>
            | undefined;
        const mailboxKeyPair = createPrivateVssMailboxKeyPair(
            fixtureHash('mailbox-key'),
        );

        const deliverySet = await createPrivateVssMailboxDeliverySet({
            kernel: {
                deriveProtocolHash: ({ namespace, value }) =>
                    deriveProtocolHash(namespace, value),
                verifyPrivateVssShareEnvelope: (input) => {
                    observedPrivateEnvelope = input.privateEnvelope as Record<
                        string,
                        unknown
                    >;
                    observedTransportedProofMaterial =
                        input.transportedPrivateVssShareProofMaterial as
                            | Record<string, unknown>
                            | undefined;

                    return {
                        ok: true,
                        privateEnvelopeHash: deriveProtocolHash(
                            'PrivateVssShareEnvelopeHash',
                            input.privateEnvelope,
                        ),
                        localVerificationRoot:
                            fixtureHash('local-verification'),
                        refusedObjects: [],
                    };
                },
            },
            setupContext,
            phaseOrderHash: fixtureHash('phase-order'),
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            vssCoefficientCommitmentRoot: fixtureHash(
                'vss-coefficient-commitment',
            ),
            qSharePrimes: [65_537],
            ringDegree: 2,
            participantCount: 1,
            deliveryPhaseNumber: 6,
            verificationPhaseNumber: 7,
            privateVssShareProofMaterialEncoding: 'binary-chunked-proof-bytes',
            privateVssShareProofFactory: () => ({
                objectType: 'PrivateVssShareProof',
                objectVersion: 1,
                proofProfileId:
                    'sealed-lattice-private-vss-share-proof-succinct-v1',
                setupProofProfileId: 'SealedLattice-LNP-SetupProof-v1',
                proofFamily: 'vss-opening-carry',
                proofBytesEncoding: 'embedded-binary-proof-bytes-hex',
                proofVerificationStatus:
                    privateVssShareSuccinctProofVerificationStatus,
                proofModelStatus: privateVssShareSuccinctProofModelStatus,
                proofStatementRoot: fixtureHash('statement-root'),
                statementHash: fixtureHash('statement-hash'),
                proofSizeBytes: proofBytes.byteLength,
                proofBytesHash,
                proofMaterialRoot: fixtureHash('embedded-material-root'),
                proofBytesHex,
            }),
            sourceTrusteeContributionStates: [
                {
                    sourceTrusteeIdentity: 'trustee-0',
                    sourceTrusteeRosterPosition: 0,
                    sourceTrusteeCommitmentRoot: fixtureHash(
                        'source-trustee-root',
                    ),
                    sourceTrusteeCoefficientCommitmentRecord: {},
                    sourceTrusteeCoefficientCommitmentMaterialRecords: [],
                    coefficientOpenings: [
                        {
                            rnsLimbIndex: 0,
                            rnsPrime: 65_537,
                            shamirCoefficientIndex: 0,
                            commitmentRoot: fixtureHash('coefficient-root'),
                            coefficientMessage: [1, 2],
                            randomnessByColumn: [[0, 1]],
                        },
                    ],
                },
            ],
            recipients: [
                {
                    recipientIdentity: 'trustee-0',
                    recipientRosterPosition: 0,
                    mailboxPublicKeyBytesHex: mailboxKeyPair.publicKeyBytesHex,
                },
            ],
        });

        expect(observedPrivateEnvelope).toBeDefined();
        const limbOpening = (
            observedPrivateEnvelope?.rnsShareOpenings as Record<
                string,
                unknown
            >[]
        )[0];
        const transportedProofRecord =
            limbOpening.privateVssShareProof as Record<string, unknown>;
        expect(transportedProofRecord.proofBytesHex).toBeUndefined();
        expect(transportedProofRecord.proofBytesEncoding).toBe(
            'binary-chunked-proof-bytes',
        );
        expect(observedTransportedProofMaterial).toBeDefined();
        expect(observedTransportedProofMaterial?.objectType).toBe(
            'SetupTransportedPrivateVssShareProofMaterialSet',
        );
        const proofMaterials =
            observedTransportedProofMaterial?.proofMaterials as Record<
                string,
                unknown
            >[];
        expect(proofMaterials).toHaveLength(1);
        expect(proofMaterials[0].proofMaterialRoot).toBe(
            transportedProofRecord.proofMaterialRoot,
        );
        expect(
            (proofMaterials[0].chunks as Record<string, unknown>[])[0]
                .bytesHex as string,
        ).toBe(proofBytesHex);
        expect(
            deliverySet.envelopeReferences[0]
                .transportedPrivateVssShareProofMaterial?.proofMaterials[0]
                .proofMaterialRoot,
        ).toBe(transportedProofRecord.proofMaterialRoot);
    });
});
