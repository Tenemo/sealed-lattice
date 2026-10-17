import { describe, expect, it } from 'vitest';

import {
    ascii,
    item,
    itemType,
    tuple,
    unsigned,
} from '#tests/node/protocol/reference/canonical-tuple.js';
import { supportedParticipantCounts } from '#tests/node/protocol/reference/product-goals.js';
import { compileRecipientKeyCensus } from '#tests/recipient-key-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';

describe('verified registration roster proposal', () => {
    it('counts the owner as a length-framed ASCII identity in the five-item role', () => {
        for (const owner of ['00'.repeat(64), 'a5'.repeat(64)]) {
            for (const position of [0, 1, 19]) {
                const encoded = tuple([
                    ascii('sealed-lattice/setup-contribution'),
                    ascii(owner),
                    item(itemType.hash512, Buffer.alloc(64, 1)),
                    item(itemType.hash512, Buffer.alloc(64, 2)),
                    item(itemType.unsigned16, unsigned(position, 2)),
                ]);
                expect(compileRosterProposalCensus(20).roleBytes).toBe(
                    BigInt(encoded.length),
                );
                expect(encoded.length).toBe(
                    6 + 5 * 6 + (4 + 33) + (4 + 128) + 2 * 64 + 2,
                );
            }
        }
    });
    it('bounds the complete public record corpus and recipient key live set', () => {
        for (const count of supportedParticipantCounts) {
            const value = compileRosterProposalCensus(count);
            expect(value.roleBytes).toBeLessThanOrEqual(1024n);
            expect(value.proposalBytes).toBeLessThan(2048n);
            const enrollment = compileRegistrationEnrollmentCensus();
            expect(value.maximumPublicCorpusBytes).toBe(
                BigInt(count) *
                    (compileRecipientKeyCensus().publicKeyBytes +
                        enrollment.maximumSourceCiphertextBytes +
                        enrollment.maximumHeaderBytes +
                        enrollment.signatureBytes) +
                    enrollment.maximumPollDefinitionBytes +
                    enrollment.signatureBytes,
            );
        }
        const value = compileRosterProposalCensus(10);
        expect(value.retainedRecipientKeyBytes).toBe(13_762_560n);
    });
    it('refuses unsupported or nonintegral roster counts', () => {
        for (const count of [2, 21, 3.5, NaN])
            expect(() => compileRosterProposalCensus(count)).toThrow();
    });
});
