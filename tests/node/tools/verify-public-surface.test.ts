import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import publicSurface from '#packages/sdk/public-surface.json' with { type: 'json' };
import {
    collectSourceExportNames,
    validatePublicSurface,
    type PublicSurfaceManifest,
} from '#tools/ci/verify-public-surface';

describe('public surface verification helpers', () => {
    it('collects runtime and type exports from the SDK facade syntax', () => {
        const sourceText = `
            import type { InternalInput } from '@sealed-lattice/types';
            export type { PublicType, InternalInput as RenamedInput } from '@sealed-lattice/types';
            export type LocalType = { readonly value: string };
            export interface LocalInterface { readonly value: string }
            export const verifyThing = (): boolean => true;
            export function deriveThing(input: unknown): unknown;
            export function deriveThing(input: unknown): unknown {
                return input;
            }
            const privateValue = true;
        `;

        expect(collectSourceExportNames(sourceText)).toEqual({
            runtimeExports: ['deriveThing', 'verifyThing'],
            typeExports: [
                'LocalInterface',
                'LocalType',
                'PublicType',
                'RenamedInput',
            ],
            unsupportedExportDeclarations: [],
        });
    });

    it('reports public manifest drift against facade exports and vendored entries', () => {
        const protocolRuntimeModuleTextByRelativePath = new Map([
            [
                'board/index.ts',
                'export const verifyBoardConsistency = (): boolean => true;',
            ],
        ]);
        const failures = validatePublicSurface({
            publicSurface: {
                runtimeExports: ['verifyBoardConsistency', 'verifyMissing'],
                publicTypeExports: ['PublicType'],
                forbiddenRuntimeExports: ['verifyBoardConsistency'],
                vendoredProtocolRuntimeModules: ['board/index.ts'],
                vendoredProtocolRuntimeEntryExports: [
                    {
                        source: 'board/index.js',
                        exports: ['verifyBoardConsistency', 'verifyMissing'],
                    },
                ],
            },
            sdkFacadeSourceText: `
                export type { PublicType } from '@sealed-lattice/types';
                export const verifyBoardConsistency = (): boolean => true;
            `,
            protocolRuntimeModuleTextByRelativePath,
        });

        expect(failures).toEqual(
            expect.arrayContaining([
                'forbiddenRuntimeExports overlaps runtimeExports at "verifyBoardConsistency"',
                'runtimeExports contains unexpected "verifyMissing"',
                'vendoredProtocolRuntimeEntryExports board/index.js does not export "verifyMissing"',
            ]),
        );
    });

    it('accepts the current public surface manifest against the SDK facade', async () => {
        const sdkFacadeSourceText = await readFile(
            'packages/sdk/src/index.ts',
            'utf8',
        );
        const protocolRuntimeModuleTextByRelativePath = new Map<
            string,
            string
        >();

        for (const relativeSourcePath of publicSurface.vendoredProtocolRuntimeModules) {
            const sourceText = await readFile(
                `packages/protocol/src/${relativeSourcePath}`,
                'utf8',
            );
            protocolRuntimeModuleTextByRelativePath.set(
                relativeSourcePath,
                sourceText,
            );
        }

        expect(
            validatePublicSurface({
                publicSurface: publicSurface as PublicSurfaceManifest,
                sdkFacadeSourceText,
                protocolRuntimeModuleTextByRelativePath,
            }),
        ).toEqual([]);
    });
});
