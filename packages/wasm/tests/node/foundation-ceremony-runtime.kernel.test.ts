import { resolve as resolvePath } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
    foundationProfile,
    isProtocolHash,
    refusalReasonCodes,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    loadFreshTranscriptCoreKernel,
    openFoundationCeremonyRuntime,
} from '#packages/wasm/src/index';
import { decodeSuiteArtifactReferences } from '#packages/wasm/src/runtime-build-canonical';
import { instantiateTranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import { createCanonicalSuiteRecordFixture } from '#packages/wasm/tests/support/canonical-suite-record-fixture';

const commonProofRawAuthorityExportFragments = [
    'attempt_binding',
    'authenticated_storage_head',
    'relation_plan',
    'storage_callback',
    'verified_capability',
] as const;
const permittedOpaqueBindingExports = new Set([
    'sealed_lattice_common_proof_generation_copy_checkpoint_stable_attempt_binding_hash',
]);

const manifestInput = () => ({
    displayTitle: 'Wybór priorytetów',
    optionDefinitions: Array.from(
        { length: foundationProfile.optionCount },
        (_value, optionIndex) => ({
            displayLabel:
                optionIndex === 4
                    ? 'Cafe\u0301'
                    : `Option ${String(optionIndex)}`,
            optionIdentifier: `option-${String(optionIndex)}`,
            optionIndex,
        }),
    ),
});

describe('foundation ceremony Rust/WASM boundary', () => {
    it('keeps raw common-proof authority internal and refuses an unselected suite', async () => {
        const commandRuntime =
            await instantiateTranscriptCoreKernelCommandRuntime(
                pathToFileURL(
                    resolvePath(
                        'packages/wasm/dist/sealed-lattice-kernel.wasm',
                    ),
                ),
                { allowUnpinnedKernel: true },
            );
        const commonProofExportNames = Object.keys(commandRuntime.wasmExports)
            .filter((exportName) =>
                exportName.startsWith('sealed_lattice_common_proof_'),
            )
            .sort();
        expect(commonProofExportNames).toEqual([
            'sealed_lattice_common_proof_abort_application',
            'sealed_lattice_common_proof_application_frame_byte_length',
            'sealed_lattice_common_proof_begin_generation',
            'sealed_lattice_common_proof_begin_verification',
            'sealed_lattice_common_proof_confirm_application',
            'sealed_lattice_common_proof_copy_selected_suite_record',
            'sealed_lattice_common_proof_describe_generation_family_adapter',
            'sealed_lattice_common_proof_describe_verification_family_adapter',
            'sealed_lattice_common_proof_discard_generation_family_adapter',
            'sealed_lattice_common_proof_discard_prepared_generation',
            'sealed_lattice_common_proof_discard_prepared_verification',
            'sealed_lattice_common_proof_discard_verification_family_adapter',
            'sealed_lattice_common_proof_discard_verified_proof',
            'sealed_lattice_common_proof_generation_acknowledge_checkpoint',
            'sealed_lattice_common_proof_generation_acknowledge_output_chunk',
            'sealed_lattice_common_proof_generation_authenticated_source_request_byte_length',
            'sealed_lattice_common_proof_generation_checkpoint_state_byte_length',
            'sealed_lattice_common_proof_generation_confirm_output_readback',
            'sealed_lattice_common_proof_generation_copy_authenticated_source_request',
            'sealed_lattice_common_proof_generation_copy_checkpoint_cursor_manifest',
            'sealed_lattice_common_proof_generation_copy_checkpoint_stable_attempt_binding_hash',
            'sealed_lattice_common_proof_generation_copy_checkpoint_state',
            'sealed_lattice_common_proof_generation_copy_external_memory_accounting',
            'sealed_lattice_common_proof_generation_copy_output_chunk',
            'sealed_lattice_common_proof_generation_copy_storage_request',
            'sealed_lattice_common_proof_generation_describe_checkpoint',
            'sealed_lattice_common_proof_generation_discard_checkpoint',
            'sealed_lattice_common_proof_generation_external_memory_accounting_byte_length',
            'sealed_lattice_common_proof_generation_finish',
            'sealed_lattice_common_proof_generation_poll',
            'sealed_lattice_common_proof_generation_release_cancelled',
            'sealed_lattice_common_proof_generation_request_cancellation',
            'sealed_lattice_common_proof_generation_retire_failed',
            'sealed_lattice_common_proof_generation_supply_authenticated_source_range',
            'sealed_lattice_common_proof_generation_supply_storage_response',
            'sealed_lattice_common_proof_prepare_application',
            'sealed_lattice_common_proof_prepare_generation_family_adapter',
            'sealed_lattice_common_proof_prepare_verification_family_adapter',
            'sealed_lattice_common_proof_release_generated_proof',
            'sealed_lattice_common_proof_release_suite',
            'sealed_lattice_common_proof_resume_generation',
            'sealed_lattice_common_proof_select_suite',
            'sealed_lattice_common_proof_selected_suite_record_byte_length',
            'sealed_lattice_common_proof_verification_absorb_input_chunk',
            'sealed_lattice_common_proof_verification_cancel',
            'sealed_lattice_common_proof_verification_copy_readback_accounting',
            'sealed_lattice_common_proof_verification_finish',
            'sealed_lattice_common_proof_verification_finish_input',
            'sealed_lattice_common_proof_verification_poll',
            'sealed_lattice_common_proof_verification_readback_accounting_byte_length',
            'sealed_lattice_common_proof_verification_supply_readback_chunk',
        ]);
        expect(
            commonProofExportNames.some((exportName) =>
                permittedOpaqueBindingExports.has(exportName)
                    ? false
                    : commonProofRawAuthorityExportFragments.some((fragment) =>
                          exportName.includes(fragment),
                      ),
            ),
        ).toBe(false);

        const selectSuite =
            commandRuntime.wasmExports.sealed_lattice_common_proof_select_suite;
        expect(selectSuite).toBeTypeOf('function');
        if (selectSuite === undefined) {
            throw new Error(
                'The generated kernel omitted the common-proof suite selector.',
            );
        }
        const suiteRecordBytes = createCanonicalSuiteRecordFixture();
        commandRuntime.runExclusive('select common-proof suite', () => {
            const suiteRecordPointer = commandRuntime.allocate(
                suiteRecordBytes.byteLength,
            );
            const statusPointer = commandRuntime.allocate(4);
            try {
                new Uint8Array(commandRuntime.memory.buffer).set(
                    suiteRecordBytes,
                    suiteRecordPointer,
                );
                new DataView(commandRuntime.memory.buffer).setUint32(
                    statusPointer,
                    0,
                    true,
                );
                const selectedSuiteHandle = selectSuite(
                    suiteRecordPointer,
                    suiteRecordBytes.byteLength,
                    statusPointer,
                );
                const refusalCode = new DataView(
                    commandRuntime.memory.buffer,
                ).getUint32(statusPointer, true);
                expect(selectedSuiteHandle).toBe(0);
                expect(refusalCode).toBe(
                    refusalReasonCodes.unsupportedVersionOrSuite,
                );
            } finally {
                commandRuntime.deallocate(statusPointer, 4);
                commandRuntime.deallocate(
                    suiteRecordPointer,
                    suiteRecordBytes.byteLength,
                );
            }
        });
    });

    it('encodes normalized manifest bytes and refuses malformed canonical bytes', async () => {
        const runtime = openFoundationCeremonyRuntime(
            await loadFreshTranscriptCoreKernel(),
        );
        const manifest = runtime.encodeManifest(manifestInput());
        const verification = runtime.verifyManifest(manifest.canonicalBytes);

        expect(verification).toEqual({
            isValid: true,
            value: { manifestHash: manifest.manifestHash },
        });

        const malformed = manifest.canonicalBytes.slice();
        malformed[malformed.length - 1] ^= 0x80;
        expect(runtime.verifyManifest(malformed)).toEqual({
            isValid: false,
            refusalReason: 'malformedEncoding',
        });
        expect(() =>
            runtime.encodeManifest({
                ...manifestInput(),
                optionDefinitions: manifestInput().optionDefinitions.slice(
                    0,
                    foundationProfile.optionCount - 1,
                ),
            }),
        ).toThrow();

        const boundaryOptionDefinitions = Array.from(
            { length: foundationProfile.optionCount },
            (_value, optionIndex) => ({
                displayLabel: `O${String(optionIndex)}`,
                optionIdentifier: `option-${String(optionIndex)}`,
                optionIndex,
            }),
        );
        const optionDisplayByteLength = boundaryOptionDefinitions.reduce(
            (total, option) => total + option.displayLabel.length,
            0,
        );
        const boundaryNonDisplayByteLength =
            30 +
            36 * boundaryOptionDefinitions.length +
            boundaryOptionDefinitions.reduce(
                (total, option) =>
                    total +
                    new TextEncoder().encode(option.optionIdentifier)
                        .byteLength,
                0,
            );
        const boundaryManifest = runtime.encodeManifest({
            displayTitle: 'Q'.repeat(
                foundationProfile.maximumCopiedBufferByteLength -
                    boundaryNonDisplayByteLength -
                    optionDisplayByteLength,
            ),
            optionDefinitions: boundaryOptionDefinitions,
        });
        expect(boundaryManifest.canonicalBytes).toHaveLength(
            foundationProfile.maximumCopiedBufferByteLength,
        );
        expect(() =>
            runtime.encodeManifest({
                displayTitle: `${'Q'.repeat(
                    foundationProfile.maximumCopiedBufferByteLength -
                        boundaryNonDisplayByteLength -
                        optionDisplayByteLength,
                )}Q`,
                optionDefinitions: boundaryOptionDefinitions,
            }),
        ).toThrow();
    });

    it('encodes action and board policy bytes under the runtime safety bounds', async () => {
        const runtime = openFoundationCeremonyRuntime(
            await loadFreshTranscriptCoreKernel(),
        );
        const actionDefinition = runtime.encodeActionDefinition({
            submissionCutoffUnixMilliseconds: 1_893_456_000_000n,
            topCount: 7,
        });
        const boardPolicy = runtime.encodeBoardPolicy({
            boardOriginIdentifier: 'https://board.example.test',
        });

        expect(
            runtime.verifyActionDefinition(actionDefinition.canonicalBytes),
        ).toEqual({
            isValid: true,
            value: {
                actionDefinitionHash: actionDefinition.actionDefinitionHash,
            },
        });
        expect(runtime.verifyBoardPolicy(boardPolicy.canonicalBytes)).toEqual({
            isValid: true,
            value: { boardPolicyHash: boardPolicy.boardPolicyHash },
        });
        expect(() =>
            runtime.encodeActionDefinition({
                submissionCutoffUnixMilliseconds: 1n << 64n,
                topCount: 7,
            }),
        ).toThrow(RangeError);
        expect(() =>
            runtime.encodeBoardPolicy({
                boardOriginIdentifier: 'board\norigin',
            }),
        ).toThrow();
    });

    it('accepts the exact suite bytes while preserving canonical framing', async () => {
        const runtime = openFoundationCeremonyRuntime(
            await loadFreshTranscriptCoreKernel(),
        );
        const suiteBytes = createCanonicalSuiteRecordFixture();
        const artifactReferences = decodeSuiteArtifactReferences(suiteBytes);

        expect(
            artifactReferences.map(({ artifactKind, byteLength }) => ({
                artifactKind,
                byteLength,
            })),
        ).toEqual([
            { artifactKind: 1, byteLength: 1n },
            { artifactKind: 2, byteLength: 1n },
            { artifactKind: 3, byteLength: 1n },
            { artifactKind: 4, byteLength: 1n },
            { artifactKind: 5, byteLength: 1n },
            { artifactKind: 6, byteLength: 1n },
        ]);
        expect(
            artifactReferences.every(
                ({ artifactHash }) => artifactHash.byteLength === 64,
            ),
        ).toBe(true);
        expect(createCanonicalSuiteRecordFixture()).toEqual(suiteBytes);
        const suiteVerification = runtime.verifySuiteRecord(suiteBytes);
        expect(suiteVerification.isValid).toBe(true);
        if (!suiteVerification.isValid) {
            throw new Error(
                `The exact suite record was refused: ${suiteVerification.refusalReason}`,
            );
        }
        expect(isProtocolHash(suiteVerification.value.suiteId)).toBe(true);

        const wrongDegreeSuiteBytes = createCanonicalSuiteRecordFixture({
            polynomialDegree: 16_384,
        });
        expect(
            decodeSuiteArtifactReferences(wrongDegreeSuiteBytes).map(
                ({ artifactKind, byteLength }) => ({
                    artifactKind,
                    byteLength,
                }),
            ),
        ).toEqual(
            artifactReferences.map(({ artifactKind, byteLength }) => ({
                artifactKind,
                byteLength,
            })),
        );
        expect(runtime.verifySuiteRecord(wrongDegreeSuiteBytes)).toEqual({
            isValid: false,
            refusalReason: 'unsupportedVersionOrSuite',
        });
        expect(runtime.verifySuiteRecord(suiteBytes.slice(0, -1))).toEqual({
            isValid: false,
            refusalReason: 'malformedEncoding',
        });
    });
});
