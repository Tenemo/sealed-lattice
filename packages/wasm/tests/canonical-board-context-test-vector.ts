import { hexToBytes } from '@noble/hashes/utils.js';
import { foundationProfile } from '@sealed-lattice/types';

import {
    openFoundationCeremonyRuntime,
    type CanonicalBoardContextInput,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import { createCanonicalSuiteRecordFixture } from '#packages/wasm/tests/support/canonical-suite-record-fixture';

export const createCanonicalBoardContextTestInput = (
    kernel: TranscriptCoreKernel,
    canonicalRosterBytes: Uint8Array,
    canonicalSuiteRecordBytes = createCanonicalSuiteRecordFixture(),
): CanonicalBoardContextInput => {
    const ceremonyRuntime = openFoundationCeremonyRuntime(kernel);
    const suite = ceremonyRuntime.verifySuiteRecord(canonicalSuiteRecordBytes);
    if (!suite.isValid) {
        throw new Error(`Suite record refused: ${suite.refusalReason}.`);
    }
    const manifest = ceremonyRuntime.encodeManifest({
        displayTitle: 'Test selection',
        optionDefinitions: Array.from(
            { length: foundationProfile.optionCount },
            (_value, optionIndex) => ({
                displayLabel: `Option ${String(optionIndex)}`,
                optionIdentifier: `option-${String(optionIndex)}`,
                optionIndex,
            }),
        ),
    });
    const ceremonyIdentifier = 'test-ceremony';
    const ceremony = ceremonyRuntime.verifyCeremonyContext({
        canonicalManifestBytes: manifest.canonicalBytes,
        canonicalRosterBytes,
        canonicalSuiteRecordBytes,
        ceremonyIdentifier,
        expectedSuiteId: suite.value.suiteId,
    });
    if (!ceremony.isValid) {
        throw new Error(`Ceremony context refused: ${ceremony.refusalReason}.`);
    }
    const actionDefinition = ceremonyRuntime.encodeActionDefinition({
        submissionCutoffUnixMilliseconds: 1_893_456_000_000n,
        topCount: 7,
    });
    const boardPolicy = ceremonyRuntime.encodeBoardPolicy({
        boardOriginIdentifier: 'board.example.test',
    });
    const actionIdentifier = 'test-action';
    const action = ceremonyRuntime.verifyActionContext({
        actionIdentifier,
        canonicalActionDefinitionBytes: actionDefinition.canonicalBytes,
        canonicalBoardPolicyBytes: boardPolicy.canonicalBytes,
        canonicalManifestBytes: manifest.canonicalBytes,
        canonicalRosterBytes,
        canonicalSuiteRecordBytes,
        ceremonyIdentifier,
        expectedCeremonyContextHash: ceremony.value.ceremonyContextHash,
        expectedSuiteId: suite.value.suiteId,
    });
    if (!action.isValid) {
        throw new Error(`Action context refused: ${action.refusalReason}.`);
    }
    return {
        actionIdentifier,
        canonicalActionDefinitionBytes: actionDefinition.canonicalBytes,
        canonicalBoardPolicyBytes: boardPolicy.canonicalBytes,
        canonicalManifestBytes: manifest.canonicalBytes,
        canonicalRosterBytes: canonicalRosterBytes.slice(),
        canonicalSuiteRecordBytes,
        ceremonyIdentifier,
        expectedActionContextHash: hexToBytes(action.value.actionContextHash),
        expectedCeremonyContextHash: hexToBytes(
            action.value.ceremonyContextHash,
        ),
        expectedSuiteIdentifier: hexToBytes(action.value.suiteId),
    };
};
