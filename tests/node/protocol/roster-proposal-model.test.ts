import { describe, expect, it } from 'vitest';

import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';

describe('verified registration roster proposal', () => {
    it('counts the owner as a length-framed ASCII identity in the five-item role', () => {
        const ascii = (text: string) => {
            const bytes = Buffer.from(text, 'ascii');
            const length = Buffer.alloc(4);
            length.writeUInt32LE(bytes.length);
            return Buffer.concat([length, bytes]);
        };
        const item = (type: number, value: Buffer) => {
            const header = Buffer.alloc(6);
            header.writeUInt16LE(type, 0);
            header.writeUInt32LE(value.length, 2);
            return Buffer.concat([header, value]);
        };
        const tuple = Buffer.from([1, 0, 1, 0, 5, 0, 0, 0]);
        for (const owner of ['00'.repeat(64), 'a5'.repeat(64)]) {
            for (const position of [0, 1, 19]) {
                const slot = Buffer.alloc(2);
                slot.writeUInt16LE(position);
                const encoded = Buffer.concat([
                    tuple,
                    item(2, ascii('sealed-lattice/setup-contribution/v2')),
                    item(2, ascii(owner)),
                    item(6, Buffer.alloc(64, 1)),
                    item(6, Buffer.alloc(64, 2)),
                    item(3, slot),
                ]);
                expect(compileRosterProposalCensus(20).roleBytes).toBe(
                    BigInt(encoded.length),
                );
                expect(encoded.length).toBe(
                    8 + 5 * 6 + (4 + 36) + (4 + 128) + 2 * 64 + 2,
                );
            }
        }
    });
    it('bounds the complete public record corpus and recipient key live set', () => {
        for (let count = 3; count <= 20; count++) {
            const value = compileRosterProposalCensus(count);
            expect(value.roleBytes).toBeLessThanOrEqual(1024n);
            expect(value.proposalBytes).toBeLessThan(2048n);
            expect(value.maximumPublicCorpusBytes).toBeLessThan(
                256n * 1024n ** 2n,
            );
        }
        const value = compileRosterProposalCensus(10);
        expect(value.retainedRecipientKeyBytes).toBe(13_762_560n);
        expect(value.maximumPublicCorpusBytes).toBeLessThan(128n * 1024n ** 2n);
    });
    it('refuses unsupported or nonintegral roster counts', () => {
        for (const count of [2, 21, 3.5, NaN])
            expect(() => compileRosterProposalCensus(count)).toThrow();
    });
});
