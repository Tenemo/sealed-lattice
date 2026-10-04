import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { open } from 'node:fs/promises';

const maximumChunkBytes = 1_048_576;

// Both native host adapters use this append-only artifact writer. No output
// is acknowledged until its bytes are written and synced; no failed write
// can be continued or completed as a proof.
/** @param {string} file @param {number} expectedBytes @param {string} expectedSha512 */
export const createSeedSharingProofSink = async (
    file,
    expectedBytes,
    expectedSha512,
) => {
    assert.ok(Number.isSafeInteger(expectedBytes) && expectedBytes > 0);
    assert.match(expectedSha512, /^[0-9a-f]{128}$/u);
    const output = await open(file, 'wx');
    const digest = createHash('sha512');
    /** @type {{index:number,offset:number,bytes:number,sha512:string}[]} */
    const chunks = [];
    let bytes = 0;
    let busy = false;
    let failed = false;
    return {
        state: () => ({ bytes, chunks: chunks.length }),
        /** @param {number} index @param {number} offset @param {Uint8Array} chunk */
        write: async (index, offset, chunk) => {
            if (failed || busy) {
                failed = true;
                throw new Error('The proof sink is failed or already writing.');
            }
            busy = true;
            try {
                assert.equal(
                    index,
                    chunks.length,
                    'The proof chunk index is out of order.',
                );
                assert.equal(
                    offset,
                    bytes,
                    'The proof chunk offset is out of order.',
                );
                assert.ok(
                    chunk instanceof Uint8Array &&
                        chunk.length > 0 &&
                        chunk.length <= maximumChunkBytes &&
                        chunk.length <= expectedBytes - bytes,
                    'The proof chunk exceeds its bound.',
                );
                const sha512 = createHash('sha512').update(chunk).digest('hex');
                let written = 0;
                while (written < chunk.length) {
                    const result = await output.write(
                        chunk,
                        written,
                        chunk.length - written,
                        offset + written,
                    );
                    assert.ok(
                        result.bytesWritten > 0,
                        'The proof chunk write made no progress.',
                    );
                    written += result.bytesWritten;
                }
                await output.sync();
                assert.ok(
                    !failed,
                    'The proof sink failed during its pending write.',
                );
                digest.update(chunk);
                chunks.push({ index, offset, bytes: chunk.length, sha512 });
                bytes += chunk.length;
                return {
                    index,
                    offset,
                    length: chunk.length,
                    sha512,
                    nextOffset: bytes,
                };
            } catch (error) {
                failed = true;
                throw error;
            } finally {
                busy = false;
            }
        },
        finish: () => {
            assert.ok(
                !failed && !busy,
                'The proof sink has no completed output.',
            );
            assert.equal(
                bytes,
                expectedBytes,
                'The generated proof is incomplete.',
            );
            const sha512 = digest.copy().digest('hex');
            if (sha512 !== expectedSha512) {
                failed = true;
                throw new Error(
                    'The generated proof does not match its pinned identity.',
                );
            }
            return { file, bytes, sha512, chunks: [...chunks] };
        },
        close: () => output.close(),
    };
};
