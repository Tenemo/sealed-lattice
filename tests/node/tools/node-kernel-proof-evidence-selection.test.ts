import { existsSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    compactPublicKeyWasmProofEvidenceCase,
    manualNodeKernelProofEvidenceTestGlobs,
    nodeKernelProofEvidenceCases,
    nodeKernelProofEvidenceProjectName,
} from '#tools/ci/node-kernel-proof-evidence-selection';
import {
    parseNodeKernelProofEvidenceArguments,
    resolveNodeKernelProofEvidenceCases,
    validateNodeKernelProofEvidenceInventoryOutput,
} from '#tools/ci/run-node-kernel-proof-evidence';

describe('Node kernel proof-evidence selection', () => {
    it('owns one existing manual file outside routine kernel execution', () => {
        expect(nodeKernelProofEvidenceProjectName).toBe(
            'node-kernel-proof-evidence',
        );
        expect(nodeKernelProofEvidenceCases).toEqual([
            compactPublicKeyWasmProofEvidenceCase,
        ]);
        expect(manualNodeKernelProofEvidenceTestGlobs).toEqual([
            compactPublicKeyWasmProofEvidenceCase.testFilePath,
        ]);
        expect(
            existsSync(
                path.resolve(
                    compactPublicKeyWasmProofEvidenceCase.testFilePath,
                ),
            ),
        ).toBe(true);
        expect(
            compactPublicKeyWasmProofEvidenceCase.testFilePath.endsWith(
                '.manual.kernel.test.ts',
            ),
        ).toBe(true);
    });

    it('resolves registered identifier, file, and test-name filters exactly', () => {
        for (const focusedFilter of [
            'scalar-wasm-same-byte',
            'compact-public-key-wasm-proof-evidence',
            'verifies the same bytes',
        ]) {
            expect(
                resolveNodeKernelProofEvidenceCases({ focusedFilter }),
            ).toEqual([compactPublicKeyWasmProofEvidenceCase]);
        }
        expect(parseNodeKernelProofEvidenceArguments([])).toEqual({});
        expect(
            parseNodeKernelProofEvidenceArguments([
                '--',
                'scalar-wasm-same-byte',
            ]),
        ).toEqual({ focusedFilter: 'scalar-wasm-same-byte' });
        expect(() =>
            validateNodeKernelProofEvidenceInventoryOutput({
                evidenceCase: compactPublicKeyWasmProofEvidenceCase,
                stdout: `[${nodeKernelProofEvidenceProjectName}] ${compactPublicKeyWasmProofEvidenceCase.testFilePath} > ${compactPublicKeyWasmProofEvidenceCase.testName}\r\n`,
            }),
        ).not.toThrow();
    });

    it('fails before execution on empty, duplicate, malformed, and zero-match selections', () => {
        expect(() =>
            resolveNodeKernelProofEvidenceCases({ configuredCases: [] }),
        ).toThrow('registry is empty');
        expect(() =>
            resolveNodeKernelProofEvidenceCases({
                configuredCases: [
                    compactPublicKeyWasmProofEvidenceCase,
                    compactPublicKeyWasmProofEvidenceCase,
                ],
            }),
        ).toThrow('malformed or duplicated');
        expect(() =>
            resolveNodeKernelProofEvidenceCases({ focusedFilter: 'absent' }),
        ).toThrow('selects zero registered cases');
        expect(() => parseNodeKernelProofEvidenceArguments([''])).toThrow(
            'filter must be non-empty',
        );
        expect(() =>
            parseNodeKernelProofEvidenceArguments(['--unknown']),
        ).toThrow('Unknown argument');
        expect(() =>
            parseNodeKernelProofEvidenceArguments(['first', 'second']),
        ).toThrow('one optional filter');
        for (const stdout of [
            '',
            `[${nodeKernelProofEvidenceProjectName}] wrong.test.ts > wrong`,
            `[${nodeKernelProofEvidenceProjectName}] ${compactPublicKeyWasmProofEvidenceCase.testFilePath} > ${compactPublicKeyWasmProofEvidenceCase.testName}\nextra`,
        ]) {
            expect(() =>
                validateNodeKernelProofEvidenceInventoryOutput({
                    evidenceCase: compactPublicKeyWasmProofEvidenceCase,
                    stdout,
                }),
            ).toThrow('inventory differs');
        }
    });
});
