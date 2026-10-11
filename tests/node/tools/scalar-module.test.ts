import binaryen from 'binaryen';
import { describe, expect, it } from 'vitest';

import { instantiateScalarModule } from '#tools/ci/scalar-module.mjs';

const entropyFixture = (owner: string) => {
    const module = binaryen.parseText(`(module
        (import "${owner}" "fill_random" (func $random (param i32 i32) (result i32)))
        (memory (export "memory") 3 4)
        (func (export "fill") (param i32 i32) (result i32) (call $random (local.get 0) (local.get 1)))
        (func (export "grow") (drop (memory.grow (i32.const 1)))))`);
    try {
        return module.emitBinary();
    } finally {
        module.dispose();
    }
};

describe('scalar source entropy boundary', () => {
    it('fills only the requested live source buffer across secure entropy chunk limits and memory growth', async () => {
        const instance = await instantiateScalarModule(
            entropyFixture('setup_witness'),
        );
        const memory = instance.exports.memory as WebAssembly.Memory;
        const fill = instance.exports.fill as (
            pointer: number,
            length: number,
        ) => number;
        for (const length of [32, 65_536, 65_537]) {
            const view = new Uint8Array(memory.buffer);
            view.fill(0);
            expect(fill(17, length)).toBe(0);
            expect(view.slice(0, 17).every((value) => value === 0)).toBe(true);
            expect(view.slice(17 + length).every((value) => value === 0)).toBe(
                true,
            );
            expect(
                view.slice(17, 17 + length).some((value) => value !== 0),
            ).toBe(true);
        }
        (instance.exports.grow as () => void)();
        expect(fill(3 * 65_536 + 7, 32)).toBe(0);
        expect(() => fill(memory.buffer.byteLength - 1, 2)).toThrow();
        expect(() => fill(-1, 1)).toThrow();
    });
    it('refuses proof randomness and every other unknown host import', async () => {
        for (const owner of ['word_proof', 'parallel', 'other'])
            await expect(
                instantiateScalarModule(entropyFixture(owner)),
            ).rejects.toThrow('Unknown scalar import');
    });
});
