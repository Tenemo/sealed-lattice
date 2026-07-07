import {
    createPrivateVssMailboxKeyPair,
    deriveCanonicalObjectHash,
    hash512Hex,
    setupProofMaterialFullObjectHashHex,
} from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import { createPrivateVssMailboxDeliverySet } from '#packages/protocol/src/index';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

const fixtureHash = makeSetupFixtureHash('setup-private-vss-mailbox-delivery');

const setupContext = makeSetupContext(fixtureHash);

describe('private VSS mailbox delivery', () => {
    it('refuses to build delivery envelopes without private share proof generation', async () => {
        await expect(
            createPrivateVssMailboxDeliverySet({
                kernel: {
                    deriveCanonicalObjectHash: ({ value }) =>
                        deriveCanonicalObjectHash(value),
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
        const textEncoder = new TextEncoder();
        const expectedFullObjectHash = setupProofMaterialFullObjectHashHex(
            'vss-opening-carry',
            proofBytes.byteLength,
            [proofBytes],
        );
        const expectedChunkHash = hash512Hex(
            'sealed-lattice/setup/proof-material/chunk-v1',
            [
                textEncoder.encode('vss-opening-carry'),
                textEncoder.encode(expectedFullObjectHash),
                Uint8Array.of(0),
                proofBytes,
            ],
        );
        const expectedChunkRoot = deriveCanonicalObjectHash({
            objectType: 'SetupProofMaterialChunkManifest',
            proofFamily: 'vss-opening-carry',
            totalByteLength: proofBytes.byteLength,
            chunkHashes: [expectedChunkHash],
            fullObjectHash: expectedFullObjectHash,
        });
        const expectedTransportedMaterialRoot = deriveCanonicalObjectHash({
            objectType: 'PrivateVssShareTransportedSuccinctProofMaterial',
            proofFamily: 'vss-opening-carry',
            proofBytesEncoding: 'binary-chunked-proof-bytes',
            statementHash: fixtureHash('statement-hash'),
            proofBytesHash,
            proofChunkCount: 1,
            proofTotalByteLength: proofBytes.byteLength,
            proofFullObjectHash: expectedFullObjectHash,
            proofChunkRoot: expectedChunkRoot,
            proofChunkHashes: [expectedChunkHash],
        });
        let observedPrivateEnvelope: Record<string, unknown> | undefined;
        let observedTransportedProofMaterial:
            | Record<string, unknown>
            | undefined;
        const mailboxKeyPair = createPrivateVssMailboxKeyPair(
            fixtureHash('mailbox-key'),
        );

        const deliverySet = await createPrivateVssMailboxDeliverySet({
            kernel: {
                deriveCanonicalObjectHash: ({ value }) =>
                    deriveCanonicalObjectHash(value),
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
                        isValid: true,
                        privateEnvelopeHash: deriveCanonicalObjectHash(
                            input.privateEnvelope,
                        ),
                        localVerificationRoot:
                            fixtureHash('local-verification'),
                        verifiedPrivateVssShareProofCount: 1,
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
                proofId: 'sealed-lattice-private-vss-share-proof-succinct-v1',
                proofFamily: 'vss-opening-carry',
                proofBytesEncoding: 'embedded-binary-proof-bytes-hex',
                proofStatementRoot: fixtureHash('statement-root'),
                statementHash: fixtureHash('statement-hash'),
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
        expect(transportedProofRecord.proofBytesEncoding).toBe(
            'binary-chunked-proof-bytes',
        );
        expect(transportedProofRecord.proofMaterialRoot).toBe(
            expectedTransportedMaterialRoot,
        );
        expect(transportedProofRecord.proofFullObjectHash).toBe(
            expectedFullObjectHash,
        );
        expect(transportedProofRecord.proofChunkRoot).toBe(expectedChunkRoot);
        expect(transportedProofRecord.proofChunkHashes).toEqual([
            expectedChunkHash,
        ]);
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
        expect(proofMaterials[0].fullObjectHash).toBe(expectedFullObjectHash);
        expect(proofMaterials[0].chunkRoot).toBe(expectedChunkRoot);
        expect(proofMaterials[0].chunkHashes).toEqual([expectedChunkHash]);
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

    it('refuses accepted local verification that omits a private VSS proof limb', async () => {
        const mailboxKeyPair = createPrivateVssMailboxKeyPair(
            fixtureHash('short-proof-count-mailbox-key'),
        );

        await expect(
            createPrivateVssMailboxDeliverySet({
                kernel: {
                    deriveCanonicalObjectHash: ({ value }) =>
                        deriveCanonicalObjectHash(value),
                    verifyPrivateVssShareEnvelope: (input) => ({
                        isValid: true,
                        privateEnvelopeHash: deriveCanonicalObjectHash(
                            input.privateEnvelope,
                        ),
                        localVerificationRoot: fixtureHash(
                            'short-proof-count-local-verification',
                        ),
                        verifiedPrivateVssShareProofCount: 1,
                        refusedObjects: [],
                    }),
                },
                setupContext,
                phaseOrderHash: fixtureHash('phase-order'),
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                vssCoefficientCommitmentRoot: fixtureHash(
                    'vss-coefficient-commitment',
                ),
                qSharePrimes: [65_537, 65_539],
                ringDegree: 2,
                participantCount: 1,
                deliveryPhaseNumber: 6,
                verificationPhaseNumber: 7,
                privateVssShareProofFactory: ({ rnsLimbIndex }) => ({
                    objectType: 'PrivateVssShareProof',
                    proofId:
                        'sealed-lattice-private-vss-share-proof-succinct-v1',
                    proofFamily: 'vss-opening-carry',
                    proofBytesEncoding: 'embedded-binary-proof-bytes-hex',
                    proofStatementRoot: fixtureHash(
                        `short-proof-count-statement-root-${String(
                            rnsLimbIndex,
                        )}`,
                    ),
                    statementHash: fixtureHash(
                        `short-proof-count-statement-hash-${String(
                            rnsLimbIndex,
                        )}`,
                    ),
                    proofBytesHash: fixtureHash(
                        `short-proof-count-proof-bytes-${String(rnsLimbIndex)}`,
                    ),
                    proofMaterialRoot: fixtureHash(
                        `short-proof-count-material-root-${String(
                            rnsLimbIndex,
                        )}`,
                    ),
                    proofBytesHex: '00010203',
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
                                commitmentRoot:
                                    fixtureHash('coefficient-root-0'),
                                coefficientMessage: [1, 2],
                                randomnessByColumn: [[0, 1]],
                            },
                            {
                                rnsLimbIndex: 1,
                                rnsPrime: 65_539,
                                shamirCoefficientIndex: 0,
                                commitmentRoot:
                                    fixtureHash('coefficient-root-1'),
                                coefficientMessage: [3, 4],
                                randomnessByColumn: [[1, 0]],
                            },
                        ],
                    },
                ],
                recipients: [
                    {
                        recipientIdentity: 'trustee-0',
                        recipientRosterPosition: 0,
                        mailboxPublicKeyBytesHex:
                            mailboxKeyPair.publicKeyBytesHex,
                    },
                ],
            }),
        ).rejects.toThrow(/verifiedPrivateVssShareProofCount/u);
    });
});
