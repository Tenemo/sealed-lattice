import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import { createFoundationCeremonyRuntimeLoader } from '../../src/foundation-ceremony-runtime.js';

const kernelUrl = new URL(
    '../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

const loadRuntime = async () =>
    createFoundationCeremonyRuntimeLoader(kernelUrl, {
        allowUnpinnedKernel: true,
    })();

const manifestInput = (optionCount: number) => ({
    displayTitle: 'Choose priorities',
    optionDefinitions: Array.from(
        { length: optionCount },
        (_unused, optionIndex) => ({
            displayLabel: `Option ${String(optionIndex)}`,
            optionIdentifier: `option-${String(optionIndex)}`,
            optionIndex,
        }),
    ),
});

describe('foundation ceremony runtime with the scalar WASM kernel', () => {
    it('exports only the owned command ABIs and standard WASM globals', async () => {
        const module = await WebAssembly.compile(await readFile(kernelUrl));
        expect(WebAssembly.Module.exports(module)).toEqual([
            { kind: 'memory', name: 'memory' },
            { kind: 'function', name: 'sealed_lattice_allocate' },
            { kind: 'function', name: 'sealed_lattice_deallocate' },
            {
                kind: 'function',
                name: 'sealed_lattice_foundation_command_with_length',
            },
            { kind: 'global', name: '__data_end' },
            { kind: 'global', name: '__heap_base' },
        ]);
    });

    it.each([2, 10, 20])(
        'roundtrips a canonical %i-option manifest through the built kernel',
        async (optionCount) => {
            const runtime = await loadRuntime();
            const encoded = runtime.encodeManifest(manifestInput(optionCount));

            expect(runtime.verifyManifest(encoded.canonicalBytes)).toEqual({
                isValid: true,
                value: { manifestHash: encoded.manifestHash },
            });
            expect(
                runtime.verifyManifest(encoded.canonicalBytes.slice(0, -1)),
            ).toEqual({
                isValid: false,
                refusalReason: 'malformedEncoding',
            });
        },
    );

    it('refuses duplicate option indexes and trailing bytes', async () => {
        const runtime = await loadRuntime();
        const duplicateIndexInput = manifestInput(2);
        duplicateIndexInput.optionDefinitions[1] = {
            ...duplicateIndexInput.optionDefinitions[1],
            optionIndex: 0,
        };
        expect(() => runtime.encodeManifest(duplicateIndexInput)).toThrow();

        const encoded = runtime.encodeManifest(manifestInput(2));
        const trailing = new Uint8Array(encoded.canonicalBytes.length + 1);
        trailing.set(encoded.canonicalBytes);
        expect(runtime.verifyManifest(trailing)).toEqual({
            isValid: false,
            refusalReason: 'malformedEncoding',
        });
    });

    it('roundtrips action and board values through the binary command boundary', async () => {
        const runtime = await loadRuntime();
        const actionDefinition = runtime.encodeActionDefinition({
            submissionCutoffUnixMilliseconds: 1_800_000_000_000n,
            topCount: 2,
        });
        expect(
            runtime.verifyActionDefinition(actionDefinition.canonicalBytes),
        ).toEqual({
            isValid: true,
            value: {
                actionDefinitionHash: actionDefinition.actionDefinitionHash,
            },
        });

        const boardPolicy = runtime.encodeBoardPolicy({
            boardOriginIdentifier: 'https://board.example',
        });
        expect(runtime.verifyBoardPolicy(boardPolicy.canonicalBytes)).toEqual({
            isValid: true,
            value: { boardPolicyHash: boardPolicy.boardPolicyHash },
        });
    });

    it('routes context verification and preserves malformed-roster refusals', async () => {
        const runtime = await loadRuntime();
        const manifest = runtime.encodeManifest(manifestInput(2));
        const actionDefinition = runtime.encodeActionDefinition({
            submissionCutoffUnixMilliseconds: 1_800_000_000_000n,
            topCount: 2,
        });
        const boardPolicy = runtime.encodeBoardPolicy({
            boardOriginIdentifier: 'https://board.example',
        });
        const emptyRoster = new Uint8Array();
        const placeholderHash = '00'.repeat(64);

        expect(
            runtime.verifyCeremonyContext({
                canonicalManifestBytes: manifest.canonicalBytes,
                canonicalRosterBytes: emptyRoster,
                ceremonyIdentifier: 'ceremony-2026',
                expectedSuiteId: placeholderHash,
            }),
        ).toEqual({
            isValid: false,
            refusalReason: 'malformedEncoding',
        });
        expect(
            runtime.verifyActionContext({
                actionIdentifier: 'submission',
                canonicalActionDefinitionBytes: actionDefinition.canonicalBytes,
                canonicalBoardPolicyBytes: boardPolicy.canonicalBytes,
                canonicalManifestBytes: manifest.canonicalBytes,
                canonicalRosterBytes: emptyRoster,
                ceremonyIdentifier: 'ceremony-2026',
                expectedCeremonyContextHash: placeholderHash,
                expectedSuiteId: placeholderHash,
            }),
        ).toEqual({
            isValid: false,
            refusalReason: 'malformedEncoding',
        });
    });
});
