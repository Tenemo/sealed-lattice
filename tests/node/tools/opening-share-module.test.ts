import binaryen from 'binaryen';
import { expect, it } from 'vitest';

import { inspectScalarProofModule } from '#tools/ci/run-seed-sharing-scalar.js';

it('requires both bounded predecessor admission and the selected opening ABI', async () => {
    const names = [
        'input_pointer',
        'input_capacity',
        'header_length',
        ...['source', 'verifier'].flatMap((role) =>
            ['begin', 'push', 'finish'].map((name) => role + '_' + name),
        ),
    ].map((name) => 'opening_' + name);
    const moduleBytes = (exports: readonly string[]) => {
        const module = binaryen.parseText(
            `(module (memory (export "memory") 1 10240) ${exports.map((name) => `(func (export "${name}") (result i32) (i32.const 0))`).join(' ')})`,
        );
        try {
            return module.emitBinary();
        } finally {
            module.dispose();
        }
    };
    await expect(
        inspectScalarProofModule(moduleBytes(names), false, 'opening-share'),
    ).resolves.toMatchObject({ imports: [] });
    await expect(
        inspectScalarProofModule(
            moduleBytes(
                names.filter((name) => name !== 'opening_source_finish'),
            ),
            false,
            'opening-share',
        ),
    ).rejects.toThrow('bounded ABI');
    await expect(
        inspectScalarProofModule(moduleBytes(names), true, 'opening-share'),
    ).rejects.toThrow('prover is missing');
    const prover = [
        'begin',
        'phase',
        'step',
        'next_output',
        'output_pointer',
        'output_length',
        'output_capacity',
        'ack_output',
    ].map((name) => 'opening_prover_' + name);
    await expect(
        inspectScalarProofModule(
            moduleBytes([...names, ...prover]),
            true,
            'opening-share',
        ),
    ).resolves.toMatchObject({ imports: [] });
});
