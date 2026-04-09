import { describe, expect, it } from 'vitest';

import packageManifest from '../../../package.json';

import * as coreModule from '#core';
import * as rootModule from '#root';

type EmptyModuleNamespace = Record<string, never>;

const loadEmptyModule = async (
    specifier: string,
): Promise<EmptyModuleNamespace> =>
    (await import(specifier)) as EmptyModuleNamespace;

const expectedExportKeys = [
    '.',
    './core',
    './proofs',
    './protocol',
    './runtime',
    './serialize',
    './threshold',
    './transport',
] as const;

const expectedImportKeys = [
    '#root',
    '#core',
    '#proofs',
    '#protocol',
    '#runtime',
    '#serialize',
    '#threshold',
    '#transport',
] as const;

describe('phase-one scaffold', () => {
    it('publishes the expected exports and imports', () => {
        expect(Object.keys(packageManifest.exports).sort()).toEqual(
            [...expectedExportKeys].sort(),
        );
        expect(Object.keys(packageManifest.imports).sort()).toEqual(
            [...expectedImportKeys].sort(),
        );
    });

    it('keeps the root and core packages intentionally tiny', () => {
        expect(Object.keys(rootModule).sort()).toEqual([
            'UnsupportedRuntimeError',
            'sha256Hex',
        ]);
        expect(Object.keys(coreModule).sort()).toEqual([
            'UnsupportedRuntimeError',
            'sha256Hex',
        ]);
    });

    it('keeps placeholder subpaths empty in phase one', async () => {
        expect(Object.keys(await loadEmptyModule('#proofs'))).toEqual([]);
        expect(Object.keys(await loadEmptyModule('#protocol'))).toEqual([]);
        expect(Object.keys(await loadEmptyModule('#runtime'))).toEqual([]);
        expect(Object.keys(await loadEmptyModule('#serialize'))).toEqual([]);
        expect(Object.keys(await loadEmptyModule('#threshold'))).toEqual([]);
        expect(Object.keys(await loadEmptyModule('#transport'))).toEqual([]);
    });
});
