import { describe, expect, it } from 'vitest';

import { encodeCandidateManifest } from '#packages/sdk/src/participant/worker/candidate-codec.js';
import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileCloseWireCensus } from '#tests/close-wire-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileOrdinaryWorkflowResources } from '#tests/ordinary-workflow-resource-model.js';
import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSetupSelectionWireCensus } from '#tests/setup-selection-wire-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

const artifact = {
    moduleBytes: 123456n,
    sdkBytes: 76543n,
    workerBytes: 70000n,
};

describe('complete ordinary workflow resource graph', () => {
    it.each(['selected', 'eligible'] as const)(
        'matches an independent emitted inventory with immutable body references for %s offers',
        (mode) => {
            const profile = deriveSupportedProfile(10, 10);
            const n = profile.participantCount;
            const result = compileOrdinaryWorkflowResources(profile, artifact);
            const registration = compileRegistrationEnrollmentCensus();
            const key = compileRegistrationKeyRelationCensus();
            const roster = compileRosterProposalCensus(n);
            const body = compileContributionBodyCensus(profile);
            const wire = compileSetupSelectionWireCensus(n);
            const ballot = compileBallotBodyCensus(profile);
            const close = compileCloseWireCensus(profile);
            const release = compileParticipantReleaseCustody(profile);
            const offers =
                mode === 'selected' ? wire.selectedCount : wire.eligibleCount;
            const chunkBytes = 1_048_576n;
            const bodies = new Map<number, string[]>();
            const objects = new Map<string, bigint>();
            let serial = 0;
            let uploaded = BigInt(offers) * 64n;
            let stored = uploaded;
            let received = 0n;
            let requests = BigInt(offers);
            let ballotManifest = 0n;
            const identity = (position: number) =>
                String(position).padStart(128, '0');
            type Entry = readonly [string, bigint, number?];
            const publish = (scope: string, entries: readonly Entry[]) => {
                let newBytes = 0n,
                    newChunks = 0n,
                    readBytes = 0n,
                    readChunks = 0n,
                    references = 0n;
                const files = entries.map(([name, length, sourceAuthor]) => {
                    const count = (length + chunkBytes - 1n) / chunkBytes;
                    const locators =
                        sourceAuthor === undefined
                            ? Array.from(
                                  { length: Number(count) },
                                  (_unused, index) => {
                                      const id = (++serial)
                                          .toString(16)
                                          .padStart(32, '0');
                                      const remaining =
                                          length - BigInt(index) * chunkBytes;
                                      const size =
                                          remaining < chunkBytes
                                              ? remaining
                                              : chunkBytes;
                                      objects.set(id, size);
                                      newBytes += size;
                                      newChunks++;
                                      return id;
                                  },
                              )
                            : bodies.get(sourceAuthor)!;
                    if (sourceAuthor !== undefined) {
                        references++;
                        readChunks += count;
                    }
                    readBytes += length;
                    return { name, length: Number(length), chunks: locators };
                });
                const encoded = BigInt(
                    encodeCandidateManifest({ files }).length,
                );
                if (/^ballot-/u.test(scope)) {
                    const author = Number(scope.slice('ballot-'.length));
                    bodies.set(
                        author,
                        files.find((entry) => entry.name === 'body.bin')!
                            .chunks,
                    );
                    ballotManifest = encoded;
                }
                uploaded += newBytes + encoded;
                stored += encoded + BigInt(Buffer.byteLength(scope)) + 16n;
                received +=
                    readBytes +
                    encoded +
                    16n * newChunks +
                    24n +
                    references * (28n + ballotManifest) +
                    12n +
                    16n * (scope === 'setup-certificate' ? BigInt(n) : 1n);
                requests += 2n * newChunks + readChunks + 2n * references + 3n;
            };
            const pollFiles: Entry[] = [
                ['definition.bin', registration.maximumPollDefinitionBytes],
                ['signature.bin', registration.signatureBytes],
            ];
            const registrationFiles: Entry[] = [
                ['polynomial-01.bin', key.publicKeyBytes],
                ['proof.bin', key.maximumProofBytes],
                ['registration-header.bin', registration.maximumHeaderBytes],
                ['signature.bin', registration.signatureBytes],
            ];
            publish('poll', pollFiles);
            for (let position = 0; position < n; position++)
                publish(
                    'registration/' + identity(position),
                    registrationFiles,
                );
            publish('poll', pollFiles);
            publish('registration/' + identity(0), registrationFiles);
            publish('roster', [
                ['proposal.bin', roster.proposalBytes],
                ['signature.bin', registration.signatureBytes],
            ]);
            for (let position = 0; position < offers; position++)
                publish(
                    'contribution-' +
                        String(position) +
                        '/' +
                        identity(position),
                    [
                        ['offer.bin', wire.offerEnvelopeBytes],
                        ['offer-signature.bin', registration.signatureBytes],
                        ['body-header.bin', body.headerBytes],
                        ...body.polynomials.map((polynomial): Entry => [
                            'polynomial-' +
                                String(polynomial.expandedIndex).padStart(
                                    2,
                                    '0',
                                ) +
                                '.bin',
                            polynomial.bytes,
                        ]),
                        ['proof.bin', body.maximumProofBytes],
                    ],
                );
            publish('selection', [
                ['selection.bin', wire.selectionBodyBytes],
                ['signature.bin', registration.signatureBytes],
            ]);
            for (let position = 0; position < n; position++) {
                publish('selection-endorsement-' + String(position), [
                    ['endorsement.bin', wire.endorsementPacketBytes],
                ]);
                publish('setup-certificate', [
                    ['certificate.bin', wire.certificateBytes],
                ]);
                publish('ballot-' + String(position), [
                    ['body.bin', ballot.maximumBodyBytes],
                    ['envelope.bin', ballot.envelopeBytes],
                    ['signature.bin', registration.signatureBytes],
                ]);
            }
            const response =
                close.minimumResponseBodyBytes +
                66n * BigInt(n) +
                4n +
                registration.signatureBytes;
            const reference = (author: number): Entry => [
                'body-' + identity(author) + '.bin',
                ballot.maximumBodyBytes,
                author,
            ];
            publish('close-intent', [['intent.bin', close.intentPacketBytes]]);
            for (let position = 0; position < n; position++)
                publish('close-response-' + String(position), [
                    ['response.bin', response],
                    ['submissions.bin', BigInt(n) * close.submissionBytes],
                    ...(position === 0
                        ? []
                        : [...bodies.keys()].map(reference)),
                ]);
            publish('close-intent', [['intent.bin', close.intentPacketBytes]]);
            publish('close-proposal', [
                ['intent.bin', close.intentPacketBytes],
                ['proposal.bin', close.proposalPacketBytes],
                ...Array.from(
                    { length: wire.quorum },
                    (_unused, position): Entry => [
                        'response-' + identity(position) + '.bin',
                        response,
                    ],
                ),
                ...Array.from({ length: n }, (_unused, position): Entry => [
                    'submission-' + identity(position) + '.bin',
                    close.submissionBytes,
                ]),
                ...[...bodies.keys()].map(reference),
            ]);
            for (let position = 0; position < n; position++) {
                publish('target-vote-' + String(position), [
                    ['vote.bin', 2n + 64n + registration.signatureBytes],
                    ...(position === 0 ? [['target.bin', 2048n] as const] : []),
                ]);
                publish('release-' + String(position), [
                    ['body.bin', release.maximumBodyBytes],
                    [
                        'envelope.bin',
                        release.envelopeBytes + registration.signatureBytes,
                    ],
                ]);
            }
            stored += [...objects.values()].reduce(
                (sum, bytes) => sum + bytes,
                0n,
            );
            const row = result.rows[mode === 'selected' ? 0 : 1];
            expect(row.publicCorpusBytes).toBe(stored);
            expect(row.totalUploadBytes).toBe(uploaded);
            expect(row.transport.receivedPayloadBytes).toBe(received);
            expect(row.transport.requests).toBe(requests);
            expect(row.workerInvocations).toBe(BigInt(12 * n + offers + 1));
        },
    );
    it.each([10, 20])(
        'charges named publication and repeated reads at %i',
        (count) => {
            const profile = deriveSupportedProfile(count, count);
            const result = compileOrdinaryWorkflowResources(profile, artifact);
            const n = BigInt(count),
                d = BigInt(Math.floor((count - 1) / 3) + 1),
                f = BigInt(Math.floor((count - 1) / 3));
            expect(result.rows.map((row) => row.offers)).toEqual([d, d + f]);
            expect(
                result.rows[1].publicCorpusBytes -
                    result.rows[0].publicCorpusBytes,
            ).toBeGreaterThan(f * (result.signedOfferBytes + 64n));
            for (const row of result.rows)
                expect(row.publicCorpusBytes - row.totalUploadBytes).toBe(
                    row.transport.publications.reduce(
                        (total, publication) =>
                            total +
                            BigInt(Buffer.byteLength(publication.key)) +
                            16n,
                        0n,
                    ),
                );
            expect(result.cleanResponseBytes).toBe(278n + 66n * n + 4n + 3309n);
            expect(result.responderListedCopyBytes).toBe(
                n * n * (214n + 3309n),
            );
            expect(result.ordinaryForwardedBodyUploadBytes).toBe(0n);
            expect(result.ordinaryReferencedBodyBytes).toBe(
                n * n * compileBallotBodyCensus(profile).maximumBodyBytes,
            );
            expect(result.maximumMissingReferenceUploadBytes).toBeGreaterThan(
                result.organizerClosureCopyBytes,
            );
            expect(result.ordinaryOrganizerDiscoveryBytes).toBe(d * 76n);
            expect(
                result.publicReaderColdDeliveryBytes -
                    result.publicReaderProtocolBytes,
            ).toBe(artifact.moduleBytes + artifact.sdkBytes);
            expect(result.bootstrapForInvocations(17n, 2n)).toBe(
                17n * artifact.moduleBytes + 2n * artifact.sdkBytes,
            );
            expect(result.bootstrapForInvocations(0n, 0n)).toBe(0n);
            // One public API call can use an evaluation worker and a fresh
            // continuation worker when its retained target cache is absent.
            expect(result.bootstrapForInvocations(2n, 1n)).toBe(
                2n * artifact.moduleBytes + artifact.sdkBytes,
            );
            expect(() => result.bootstrapForInvocations(-1n, 0n)).toThrow(
                'Negative',
            );
            expect(result.retainedTarget.ciphertextBytes).toBe(
                2n * 65536n * 25n,
            );
            expect(result.retainedTarget.maximumRetainedBytes).toBe(
                4n + 4n + 2048n + 2n * 65536n * 25n + 64n,
            );
            expect(result.retainedTarget.maximumSliceBytes).toBe(1048576n);
            expect(result.retainedTarget.maximumSlices).toBe(4n);
            expect(result.maximumPublicationRecordBytes).toBe(1_048_576n);
            expect(result.publicationRecordPayloadReadBytes).toBeGreaterThan(
                2n * result.registrationCorpusBytes,
            );
        },
    );

    it('keeps the ordinary/all-eligible and standalone-reader planning conclusions separate', () => {
        const ten = compileOrdinaryWorkflowResources(
            deriveSupportedProfile(10, 10),
            artifact,
        );
        const twenty = compileOrdinaryWorkflowResources(
            deriveSupportedProfile(20, 20),
            artifact,
        );
        expect(ten.rows[0].publicCorpusBytes).toBeLessThan(ten.planningBytes);
        expect(ten.rows[0].totalUploadBytes).toBeLessThan(ten.planningBytes);
        expect(ten.publicReaderProtocolBytes).toBeLessThan(ten.planningBytes);
        expect(ten.rows[1].publicCorpusBytes).toBeGreaterThan(
            ten.planningBytes,
        );
        expect(ten.rows[1].publicCorpusBytes).toBeLessThan(
            ten.planningVarianceCeilingBytes,
        );
        expect(twenty.rows[0].publicCorpusBytes).toBeGreaterThan(
            twenty.planningVarianceCeilingBytes,
        );
        expect(twenty.publicReaderProtocolBytes).toBeGreaterThan(
            twenty.planningVarianceCeilingBytes,
        );
        expect(() =>
            compileOrdinaryWorkflowResources(deriveSupportedProfile(3, 2), {
                ...artifact,
                moduleBytes: 0n,
            }),
        ).toThrow('artifact');
    });
});
