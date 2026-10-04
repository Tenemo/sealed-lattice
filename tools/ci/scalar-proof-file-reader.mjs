import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { open } from 'node:fs/promises';

/** @typedef {{file:string,bytes:number,sha512:string}} Proof */
/** @param {string} file */
const digestFile = async (file) => {
    const digest = createHash('sha512');
    for await (const chunk of createReadStream(file)) {
        assert.ok(chunk instanceof Uint8Array);
        digest.update(chunk);
    }
    return digest.digest('hex');
};

// One reusable read buffer serves all sequential proof streams. Every file
// is authenticated before the callback and checked again after it finishes.
/** @template T @param {Proof[]} proofs @param {(read:(index:number,length:number,position:number)=>Promise<Uint8Array>)=>Promise<T>} operation */
export const withPinnedProofReaders = async (proofs, operation) => {
    const files = [];
    const buffer = new Uint8Array(1_048_576);
    try {
        for (const proof of proofs) {
            assert.equal(await digestFile(proof.file), proof.sha512);
            const file = await open(proof.file, 'r');
            files.push(file);
            assert.equal((await file.stat()).size, proof.bytes);
        }
        let reading = false;
        const result = await operation(async (index, length, position) => {
            assert.ok(
                !reading &&
                    Number.isSafeInteger(index) &&
                    index >= 0 &&
                    index < files.length &&
                    Number.isSafeInteger(length) &&
                    length > 0 &&
                    length <= buffer.length &&
                    Number.isSafeInteger(position) &&
                    position >= 0 &&
                    position + length <= proofs[index].bytes,
                'A proof read exceeds its pinned bound.',
            );
            reading = true;
            try {
                let filled = 0;
                while (filled < length) {
                    const { bytesRead } = await files[index].read(
                        buffer,
                        filled,
                        length - filled,
                        position + filled,
                    );
                    assert.ok(
                        bytesRead > 0,
                        'The pinned proof ended during a bounded read.',
                    );
                    filled += bytesRead;
                }
                return buffer.subarray(0, length);
            } finally {
                reading = false;
            }
        });
        for (const proof of proofs)
            assert.equal(await digestFile(proof.file), proof.sha512);
        return result;
    } finally {
        buffer.fill(0);
        await Promise.all(files.map((file) => file.close()));
    }
};
