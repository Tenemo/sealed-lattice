import binaryen from 'binaryen';
import { expect, it } from 'vitest';

import { inspectScalarFixtureModule } from '#tools/ci/scalar-fixture-build.js';

it('admits the public operator ABI without a proof or verifier export surface', async () => {
    const names = [
        'begin',
        'phase',
        'step',
        'next_output',
        'output_pointer',
        'output_length',
        'output_capacity',
        'ack_output',
    ].map((name) => 'operator_screen_' + name);
    const module = binaryen.parseText(
        `(module (memory (export "memory") 1 10240) ${names.map((name) => `(func (export "${name}") (result i32) (i32.const 0))`).join(' ')})`,
    );
    try {
        const bytes = module.emitBinary();
        await expect(
            inspectScalarFixtureModule(bytes, false, 'public-operator'),
        ).resolves.toMatchObject({ imports: [] });
        await expect(
            inspectScalarFixtureModule(bytes, true, 'public-operator'),
        ).rejects.toThrow('no proof-generation mode');
        await expect(
            inspectScalarFixtureModule(bytes, false, 'opening-share'),
        ).rejects.toThrow('bounded ABI');
    } finally {
        module.dispose();
    }
});

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
        inspectScalarFixtureModule(moduleBytes(names), false, 'opening-share'),
    ).resolves.toMatchObject({ imports: [] });
    await expect(
        inspectScalarFixtureModule(
            moduleBytes(
                names.filter((name) => name !== 'opening_source_finish'),
            ),
            false,
            'opening-share',
        ),
    ).rejects.toThrow('bounded ABI');
    await expect(
        inspectScalarFixtureModule(moduleBytes(names), true, 'opening-share'),
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
        inspectScalarFixtureModule(
            moduleBytes([...names, ...prover]),
            true,
            'opening-share',
        ),
    ).resolves.toMatchObject({ imports: [] });
});
