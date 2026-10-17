import { createCompactRankVerifier } from './compact-rank-scalar.mjs';

onmessage = async () => {
    try {
        const module = await WebAssembly.compile(
            await (await fetch('/module.wasm')).arrayBuffer(),
        );
        let verifier = await createCompactRankVerifier(module);
        const cases =
            /** @type {{name:string,url:string,accepted:boolean}[]} */ (
                await (await fetch('/fixtures.json')).json()
            );
        if (!cases.length)
            throw new Error('The browser rank fixture list is empty.');
        const reports = [];
        let maximumLinearMemory = 0;
        for (const entry of [
            ...cases,
            cases.find((candidate) => candidate.accepted),
        ]) {
            if (!entry)
                throw new Error(
                    'The browser rank screen has no positive fixture.',
                );
            if (reports.length === cases.length)
                verifier = await createCompactRankVerifier(module);
            const bytes = new Uint8Array(
                await (await fetch(entry.url)).arrayBuffer(),
            );
            const started = performance.now();
            const result = verifier.verify(bytes);
            if (result.accepted !== entry.accepted)
                throw new Error('Wrong browser rank verdict: ' + entry.name);
            if (
                entry.name === 'original-input-binding-counterexample' &&
                result.refusal !== 'Relation'
            )
                throw new Error(
                    'The original input-binding counterexample did not reach the relation check.',
                );
            maximumLinearMemory = Math.max(
                maximumLinearMemory,
                verifier.memoryBytes(),
            );
            reports.push({
                name:
                    reports.length === cases.length
                        ? 'fresh-instance-replay'
                        : entry.name,
                ...result,
                milliseconds: performance.now() - started,
            });
        }
        postMessage({
            result: {
                kind: 'compact-rank-proof',
                host: 'browser',
                cases: reports,
                maximumLinearMemory,
            },
        });
    } catch (error) {
        postMessage({
            error: error instanceof Error ? error.message : String(error),
        });
    }
};
