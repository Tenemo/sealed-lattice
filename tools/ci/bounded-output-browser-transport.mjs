// Each authenticated output chunk crosses the transport alone and within
// this bound.
export const browserChunkBytes = 1_048_576;

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

/**
 * @param {string} sinkUrl
 * @param {number} index
 * @param {number} offset
 * @param {Uint8Array<ArrayBuffer>} bytes
 * @param {typeof fetch} [fetchBytes]
 */
export const emitBrowserOutputChunk = async (
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
        bytes.length > browserChunkBytes
    )
        throw new Error('The output chunk exceeds its transport bounds.');
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
            'The output sink did not acknowledge the written chunk.',
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
                'The output sink acknowledgment has an invalid coordinate.',
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
        throw new Error('The output sink acknowledged another chunk.');
    return receipt;
};
