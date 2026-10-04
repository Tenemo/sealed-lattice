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

/**
 * @param {string} sinkUrl
 * @param {number} index
 * @param {number} offset
 * @param {Uint8Array<ArrayBuffer>} bytes
 * @param {typeof fetch} [fetchBytes]
 */
export const emitBrowserProofChunk = async (
    sinkUrl,
    index,
    offset,
    bytes,
    fetchBytes = fetch,
) => {
    if (
        !Number.isSafeInteger(index) ||
        index < 0 ||
        !Number.isSafeInteger(offset) ||
        offset < 0 ||
        bytes.length === 0 ||
        bytes.length > seedSharingChunkBytes
    )
        throw new Error(
            'The generated proof chunk exceeds its transport bounds.',
        );
    const sha512 = await browserSha512(bytes);
    const response = await fetchBytes(sinkUrl + index + '/' + offset, {
        method: 'POST',
        body: bytes,
        headers: { 'X-Chunk-Sha512': sha512 },
    });
    if (
        response.status !== 204 ||
        response.headers.get('X-Chunk-Sha512') !== sha512
    )
        throw new Error(
            'The proof sink did not acknowledge the written chunk.',
        );
    /** @param {string} name */
    const coordinate = (name) => {
        const value = response.headers.get(name);
        if (
            value === null ||
            !/^(0|[1-9][0-9]*)$/u.test(value) ||
            !Number.isSafeInteger(Number(value))
        )
            throw new Error(
                'The proof sink acknowledgment has an invalid coordinate.',
            );
        return Number(value);
    };
    const receipt = {
        index: coordinate('X-Chunk-Index'),
        offset: coordinate('X-Chunk-Offset'),
        length: coordinate('X-Chunk-Length'),
    };
    if (
        receipt.index !== index ||
        receipt.offset !== offset ||
        receipt.length !== bytes.length ||
        coordinate('X-Next-Offset') !== offset + bytes.length
    )
        throw new Error('The proof sink acknowledged another chunk.');
    return receipt;
};

// Predecessors are verified sequentially. Only the active predecessor keeps
// a transport cache, and its last full read releases that cache before the
// opening proof or private prover begins.
/** @param {readonly BrowserProof[]} predecessors @param {typeof fetch} [fetchBytes] */
export const createBrowserPredecessorReader = (
    predecessors,
    fetchBytes = fetch,
) => {
    /** @type {{index:number,read:ReturnType<typeof createBrowserProofReader>} | undefined} */
    let active;
    const release = () => {
        active = undefined;
    };
    return {
        release,
        /** @param {number} index @param {number} length @param {number} position */
        read: async (index, length, position) => {
            if (
                !Number.isSafeInteger(index) ||
                index < 0 ||
                index >= predecessors.length
            )
                throw new Error(
                    'The predecessor index is outside its pinned inputs.',
                );
            if (active?.index !== index) {
                release();
                active = {
                    index,
                    read: createBrowserProofReader(
                        predecessors[index],
                        fetchBytes,
                    ),
                };
            }
            const bytes = await active.read(length, position);
            if (position + length === predecessors[index].bytes) release();
            return bytes;
        },
    };
};
