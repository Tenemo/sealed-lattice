import { describe, expect, it } from 'vitest';

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
        'matches an independently enumerated named-publication inventory for %s offers',
        (mode) => {
            const profile = deriveSupportedProfile(10, 10),
                n = profile.participantCount;
            const result = compileOrdinaryWorkflowResources(profile, artifact);
            const registration = compileRegistrationEnrollmentCensus(),
                key = compileRegistrationKeyRelationCensus(),
                roster = compileRosterProposalCensus(n);
            const body = compileContributionBodyCensus(profile),
                wire = compileSetupSelectionWireCensus(n),
                ballot = compileBallotBodyCensus(profile),
                close = compileCloseWireCensus(profile),
                release = compileParticipantReleaseCustody(profile);
            const files = new Map<string, bigint>();
            let uploads = 0n;
            const publish = (name: string, bytes: bigint) => {
                const existing = files.get(name);
                if (existing !== undefined && existing !== bytes)
                    throw new Error('Changed named record.');
                files.set(name, bytes);
                uploads += bytes;
            };
            const registrationFiles = (position: number) => {
                publish(
                    `registration/${position}/header`,
                    registration.maximumHeaderBytes,
                );
                publish(`registration/${position}/key`, key.publicKeyBytes);
                publish(
                    `registration/${position}/proof`,
                    key.maximumProofBytes,
                );
                publish(
                    `registration/${position}/signature`,
                    registration.signatureBytes,
                );
            };
            const poll = () => {
                publish('poll', registration.maximumPollDefinitionBytes);
                publish('poll-signature', registration.signatureBytes);
            };
            poll();
            for (let position = 0; position < n; position++)
                registrationFiles(position);
            // The roster publication currently sends the organizer's earlier
            // enrollment and poll again before the new signed proposal.
            poll();
            registrationFiles(0);
            publish('proposal', roster.proposalBytes);
            publish('proposal-signature', registration.signatureBytes);
            const offers =
                mode === 'selected' ? wire.selectedCount : wire.eligibleCount;
            for (let position = 0; position < offers; position++) {
                publish(`offer/${position}/body`, body.maximumBodyBytes);
                publish(`offer/${position}/envelope`, wire.offerEnvelopeBytes);
                publish(
                    `offer/${position}/signature`,
                    registration.signatureBytes,
                );
                publish(`announcements/${position}`, 64n);
            }
            publish('selection', wire.selectionBodyBytes);
            publish('selection-signature', registration.signatureBytes);
            for (let position = 0; position < n; position++) {
                publish(`endorsement/${position}`, wire.endorsementPacketBytes);
                publish('certificate', wire.certificateBytes);
                publish('setup-selector', 64n);
                publish(`ballot/${position}/body`, ballot.maximumBodyBytes);
                publish(`ballot/${position}/envelope`, ballot.envelopeBytes);
                publish(
                    `ballot/${position}/signature`,
                    registration.signatureBytes,
                );
                publish(`ballot/${position}/pointer`, 64n);
            }
            publish('close/intent', close.intentPacketBytes);
            publish('close/held', 64n * BigInt(n));
            const response =
                close.minimumResponseBodyBytes +
                66n * BigInt(n) +
                4n +
                registration.signatureBytes;
            for (let position = 0; position < n; position++) {
                publish(`close/response/${position}`, response);
                if (position > 0)
                    publish(
                        `close/listed/${position}`,
                        BigInt(n) * close.submissionBytes,
                    );
            }
            for (let position = 0; position < wire.quorum; position++)
                publish(`closure/response/${position}`, response);
            for (let position = 0; position < n; position++) {
                publish(
                    `closure/submission/${position}`,
                    close.submissionBytes,
                );
                if (position > 0)
                    publish(
                        `closure/body/${position}`,
                        ballot.maximumBodyBytes,
                    );
            }
            publish('close/intent', close.intentPacketBytes);
            publish('close/held', 64n * BigInt(n));
            publish('close/proposal', close.proposalPacketBytes);
            for (let position = 0; position < n; position++) {
                publish(
                    `target-vote/${position}`,
                    2n + 64n + registration.signatureBytes,
                );
                publish(`release/${position}/body`, release.maximumBodyBytes);
                publish(
                    `release/${position}/envelope`,
                    release.envelopeBytes + registration.signatureBytes,
                );
            }
            publish('target', 2048n);
            const row = result.rows[mode === 'selected' ? 0 : 1];
            expect(
                [...files.values()].reduce((sum, bytes) => sum + bytes, 0n),
            ).toBe(row.publicCorpusBytes);
            expect(uploads).toBe(row.totalUploadBytes);
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
            ).toBe(f * (result.signedOfferBytes + 64n));
            expect(
                result.rows.map(
                    (row) => row.totalUploadBytes - row.publicCorpusBytes,
                ),
            ).toEqual([
                result.duplicateUploadBytes,
                result.duplicateUploadBytes,
            ]);
            expect(result.cleanResponseBytes).toBe(278n + 66n * n + 4n + 3309n);
            expect(result.responderListedCopyBytes).toBe(
                n * (n - 1n) * (214n + 3309n),
            );
            expect(result.ordinaryForwardedBodyBytes).toBe(0n);
            expect(result.maximumForwardedBodyFallbackBytes).toBeGreaterThan(
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
