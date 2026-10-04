// Scalar execution has no helper workers. Only the actual helper-count
// query returns zero; every other host operation must fail if called.
/** @param {Uint8Array} bytes @param {{operation:'generation'|'verification'|'operator',allowRandomnessFallback?:boolean}} options */
export const instantiateScalarModule = async (
    bytes,
    { operation, allowRandomnessFallback = false },
) => {
    const unavailable = (name) => () => {
        throw new Error('Scalar ' + operation + ' invoked ' + name);
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
        word_proof: { fill_random: unavailable('word_proof.fill_random') },
    };
    const compiled = await WebAssembly.compile(bytes);
    for (const entry of WebAssembly.Module.imports(compiled)) {
        if (
            entry.kind !== 'function' ||
            !(
                (entry.module === 'parallel' &&
                    Object.keys(imports.parallel).includes(entry.name)) ||
                (allowRandomnessFallback &&
                    entry.module === 'word_proof' &&
                    entry.name === 'fill_random')
            )
        )
            throw new Error('Unknown scalar import.');
    }
    return WebAssembly.instantiate(compiled, imports);
};
