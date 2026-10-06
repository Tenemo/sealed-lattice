// Scalar execution has no helper workers. Only the actual helper-count
// query returns zero, and only the key source screen's setup entropy request
// is served; every other host operation must fail if called.
/** @param {Uint8Array} bytes */
export const instantiateScalarModule = async (bytes) => {
    /** @type {WebAssembly.Instance|undefined} */
    let instance;
    const unavailable = (name) => () => {
        throw new Error('Scalar fhe-key-source invoked ' + name);
    };
    const imports = {
        parallel: {
            helpers: () => 0,
            share: unavailable('parallel.share'),
            release: unavailable('parallel.release'),
            submit: unavailable('parallel.submit'),
            wait: unavailable('parallel.wait'),
            take: unavailable('parallel.take'),
            discard: unavailable('parallel.discard'),
            ended: unavailable('parallel.ended'),
            read: unavailable('parallel.read'),
        },
        setup_witness: {
            /** @param {number} pointer @param {number} length */
            fill_random: (pointer, length) => {
                const memory = instance?.exports.memory;
                if (
                    !(memory instanceof WebAssembly.Memory) ||
                    !Number.isSafeInteger(pointer) ||
                    pointer < 0 ||
                    !Number.isSafeInteger(length) ||
                    length < 0 ||
                    pointer + length > memory.buffer.byteLength
                )
                    throw new Error('Invalid key source entropy request.');
                for (let offset = 0; offset < length; offset += 65_536)
                    crypto.getRandomValues(
                        new Uint8Array(
                            memory.buffer,
                            pointer + offset,
                            Math.min(65_536, length - offset),
                        ),
                    );
                return 0;
            },
        },
    };
    const compiled = await WebAssembly.compile(bytes);
    for (const entry of WebAssembly.Module.imports(compiled)) {
        if (
            entry.kind !== 'function' ||
            !(
                (entry.module === 'parallel' &&
                    Object.keys(imports.parallel).includes(entry.name)) ||
                (entry.module === 'setup_witness' &&
                    entry.name === 'fill_random')
            )
        )
            throw new Error('Unknown scalar import.');
    }
    instance = await WebAssembly.instantiate(compiled, imports);
    return instance;
};
