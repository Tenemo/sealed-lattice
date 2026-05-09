import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
    collectDeclaredExportValueNames,
    collectExportedTypeAliases,
    collectNamedImportsFromModule,
    collectStringSetValues,
    collectStringUnionValues,
    collectTypeExportSpecifiers,
    findSdkSurfaceFailures,
} from '../../../tools/ci/verify-sdk-surface';

const loadRepositorySources = (): Parameters<
    typeof findSdkSurfaceFailures
>[0] => ({
    protocolIndexText: readFileSync('packages/protocol/src/index.ts', 'utf8'),
    protocolShellIndexText: readFileSync(
        'packages/protocol/src/protocol-shell/index.ts',
        'utf8',
    ),
    protocolShellTypesText: readFileSync(
        'packages/protocol/src/protocol-shell/types.ts',
        'utf8',
    ),
    sdkIndexText: readFileSync('packages/sdk/src/index.ts', 'utf8'),
    sdkKernelText: readFileSync('packages/sdk/src/kernel.ts', 'utf8'),
    sdkProtocolShellDeclarationText: readFileSync(
        'packages/sdk/src/internal/protocol-shell/index.d.ts',
        'utf8',
    ),
    sdkTranscriptCoreBridgeDeclarationText: readFileSync(
        'packages/sdk/src/internal/transcript-core-bridge.d.ts',
        'utf8',
    ),
    sdkTypesText: readFileSync('packages/sdk/src/types.ts', 'utf8'),
    wasmTranscriptCoreBridgeText: readFileSync(
        'packages/wasm/src/transcript-core-bridge.ts',
        'utf8',
    ),
});

describe('SDK surface verification helpers', () => {
    it('collects exported type aliases and public type re-exports', () => {
        const sourceText = `
            export type PublicState = 'Ready' | 'Rejected';
            type PrivateState = 'Ignored';
            export type Box = { readonly value: PublicState };
            export type { PublicState as ExportedState, Box } from './types.js';
        `;

        expect([...collectExportedTypeAliases(sourceText).keys()]).toEqual([
            'PublicState',
            'Box',
        ]);
        expect(collectTypeExportSpecifiers(sourceText, './types.js')).toEqual([
            'Box',
            'PublicState',
        ]);
    });

    it('collects string unions and literal string sets', () => {
        expect(
            collectStringUnionValues(
                "export type RefusalReason = 'A' | 'B' | 'C';",
                'RefusalReason',
            ),
        ).toEqual(['A', 'B', 'C']);
        expect(
            collectStringSetValues(
                "const canonicalErrorCodes = new Set<string>(['B', 'A']);",
                'canonicalErrorCodes',
            ),
        ).toEqual(['A', 'B']);
        expect(
            collectStringUnionValues(
                'export type Structured = { readonly value: string };',
                'Structured',
            ),
        ).toBeUndefined();
    });

    it('uses original imported names when imports are aliased', () => {
        const sourceText = `
            import {
                deriveThresholdProfile as deriveThresholdProfileInternal,
                validatePollSpec,
            } from './internal/protocol-shell/index.js';

            export declare const validatePollSpec: () => void;
        `;

        expect(
            collectNamedImportsFromModule(
                sourceText,
                './internal/protocol-shell/index.js',
            ),
        ).toEqual(['deriveThresholdProfile', 'validatePollSpec']);
        expect(collectDeclaredExportValueNames(sourceText)).toEqual([
            'validatePollSpec',
        ]);
    });

    it('reports drift in public string unions and bridge guards', () => {
        const sources = loadRepositorySources();
        const failures = findSdkSurfaceFailures({
            ...sources,
            sdkTypesText: sources.sdkTypesText.replace(
                "| 'InvalidHex'",
                "| 'InvalidHex' | 'UnexpectedErrorCode'",
            ),
        });

        expect(failures).toEqual(
            expect.arrayContaining([
                expect.stringContaining('CanonicalErrorCode'),
                expect.stringContaining('UnexpectedErrorCode'),
            ]),
        );
    });

    it('accepts the checked-in SDK facade and internal declarations', () => {
        expect(findSdkSurfaceFailures(loadRepositorySources())).toEqual([]);
    });
});
