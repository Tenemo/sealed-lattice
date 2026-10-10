import binaryen from 'binaryen';
import { describe, expect, it } from 'vitest';

import { inspectScalarFixtureModule } from '#tools/ci/scalar-fixture-build.js';

const screenExports = [
    'begin',
    'phase',
    'step',
    'next_output',
    'output_pointer',
    'output_length',
    'output_capacity',
    'ack_output',
] as const;

const moduleBytes = ({
    memory = '(memory (export "memory") 1 10240)',
    extra = '',
    exports = screenExports,
}: {
    memory?: string;
    extra?: string;
    exports?: readonly string[];
} = {}) => {
    const module = binaryen.parseText(
        `(module ${extra} ${memory} ${exports.map((name) => `(func (export "key_source_screen_${name}") (result i32) (i32.const 0))`).join(' ')})`,
    );
    try {
        return module.emitBinary();
    } finally {
        module.dispose();
    }
};

describe('scalar key source module admission', () => {
    it('admits a scalar, bounded, unshared screen module with only its known host imports', async () => {
        await expect(
            inspectScalarFixtureModule(moduleBytes()),
        ).resolves.toMatchObject({ imports: [] });
        await expect(
            inspectScalarFixtureModule(
                moduleBytes({
                    extra: '(import "parallel" "helpers" (func (result i32))) (import "setup_witness" "fill_random" (func (param i32 i32) (result i32)))',
                }),
            ),
        ).resolves.toMatchObject({
            imports: [
                { module: 'parallel', name: 'helpers', kind: 'function' },
                {
                    module: 'setup_witness',
                    name: 'fill_random',
                    kind: 'function',
                },
            ],
        });
    });

    it('refuses proof randomness, unknown or non-function imports, an incomplete screen ABI, unbounded or shared memory and vector instructions', async () => {
        for (const extra of [
            '(import "word_proof" "fill_random" (func (param i32 i32) (result i32)))',
            '(import "parallel" "spawn" (func))',
            '(import "setup_witness" "read" (func))',
            '(import "parallel" "helpers" (global i32))',
        ])
            await expect(
                inspectScalarFixtureModule(moduleBytes({ extra })),
            ).rejects.toThrow('unknown host import');
        for (const missing of screenExports)
            await expect(
                inspectScalarFixtureModule(
                    moduleBytes({
                        exports: screenExports.filter(
                            (name) => name !== missing,
                        ),
                    }),
                ),
            ).rejects.toThrow('missing its bounded ABI');
        await expect(
            inspectScalarFixtureModule(
                moduleBytes({ memory: '(memory (export "heap") 1 10240)' }),
            ),
        ).rejects.toThrow();
        for (const memory of [
            '(memory (export "memory") 1 16384)',
            '(memory (export "memory") 1)',
            '(memory (export "memory") 1 10240 shared)',
        ])
            await expect(
                inspectScalarFixtureModule(moduleBytes({ memory })),
            ).rejects.toThrow('bounded unshared');
        await expect(
            inspectScalarFixtureModule(
                moduleBytes({
                    extra: '(func (drop (v128.const i32x4 0 0 0 0)))',
                }),
            ),
        ).rejects.toThrow('scalar instructions');
    });
});
