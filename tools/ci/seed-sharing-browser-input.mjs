// One authenticated transport chunk and one bounded read buffer are retained.
export const seedSharingChunkBytes = 1_048_576;

/** @param {Uint8Array<ArrayBuffer>} bytes */
export const browserSha512 = async (bytes) =>
    Array.from(
        new Uint8Array(await crypto.subtle.digest('SHA-512', bytes)),
        (value) => value.toString(16).padStart(2, '0'),
    ).join('');

/**
 * @param {string} url
 * @param {number} length
 * @param {number} maximum
 * @param {typeof fetch} [fetchBytes]
 */
export const readBoundedBrowserResponse = async (
    url,
    length,
    maximum,
    fetchBytes = fetch,
) => {
    if (!Number.isSafeInteger(length) || length <= 0 || length > maximum)
        throw new Error('The browser input length exceeds its bound.');
    const response = await fetchBytes(url, { cache: 'no-store' });
    if (!response.ok || response.body === null)
        throw new Error('The pinned browser input is unavailable.');
    const output = new Uint8Array(length);
    const reader = response.body.getReader();
    let offset = 0;
    try {
        for (;;) {
            const { value, done } = await reader.read();
            if (done) break;
            if (value.length > length - offset)
                throw new Error(
                    'The pinned browser input exceeds its declared length.',
                );
            output.set(value, offset);
            offset += value.length;
        }
        if (offset !== length)
            throw new Error(
                'The pinned browser input ended before its declared length.',
            );
        return output;
    } catch (error) {
        await reader.cancel().catch(() => undefined);
        throw error;
    } finally {
        reader.releaseLock();
    }
};

/** @typedef {{bytes:number, url:string, chunks:readonly {offset:number,bytes:number,sha512:string}[]}} BrowserProof */
/** @param {BrowserProof} proof @param {typeof fetch} [fetchBytes] */
export const createBrowserProofReader = (proof, fetchBytes = fetch) => {
    /** @type {{index:number,bytes:Uint8Array<ArrayBuffer>} | undefined} */
    let cached;
    /** @param {number} length @param {number} position */
    return async (length, position) => {
        if (
            !Number.isSafeInteger(length) ||
            length <= 0 ||
            length > seedSharingChunkBytes ||
            !Number.isSafeInteger(position) ||
            position < 0 ||
            position + length > proof.bytes
        )
            throw new Error('The proof read lies outside its pinned bounds.');
        const output = new Uint8Array(length);
        let copied = 0;
        while (copied < length) {
            const index = Math.floor(
                (position + copied) / seedSharingChunkBytes,
            );
            const chunk = proof.chunks[index];
            if (
                chunk === undefined ||
                chunk.offset !== index * seedSharingChunkBytes ||
                chunk.bytes !==
                    Math.min(seedSharingChunkBytes, proof.bytes - chunk.offset)
            )
                throw new Error('The proof chunk inventory is inconsistent.');
            if (cached?.index !== index) {
                cached = undefined;
                const bytes = await readBoundedBrowserResponse(
                    proof.url + index,
                    chunk.bytes,
                    seedSharingChunkBytes,
                    fetchBytes,
                );
                if ((await browserSha512(bytes)) !== chunk.sha512)
                    throw new Error(
                        'The proof chunk does not match its pinned identity.',
                    );
                cached = { index, bytes };
            }
            const within = position + copied - chunk.offset;
            const amount = Math.min(length - copied, chunk.bytes - within);
            output.set(cached.bytes.subarray(within, within + amount), copied);
            copied += amount;
        }
        return output;
    };
};
