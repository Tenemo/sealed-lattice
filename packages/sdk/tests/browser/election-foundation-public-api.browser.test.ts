import type {
    BoardConsistencyInput,
    BoardConsistencyVerification,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import * as publicApiRuntime from '../../dist/index.js';

type VerifyBoardConsistency = (
    input: BoardConsistencyInput,
) => BoardConsistencyVerification;

const publicApiRuntimeRecord = publicApiRuntime as Record<string, unknown>;
const verifyBoardConsistency =
    publicApiRuntimeRecord.verifyBoardConsistency as VerifyBoardConsistency;
const requiredPublicFunctionNames = [
    'deriveThresholdParameters',
    'validatePollSpec',
    'evaluateActionCapability',
    'deriveValidatedFirstValidOrder',
    'verifyBoardConsistency',
    'verifyFoundationTranscript',
] as const;

describe('election foundation public package API in browsers', () => {
    it('exposes callable safe runtime functions', () => {
        const runtimeExportNames = Object.keys(publicApiRuntimeRecord).sort();

        expect(runtimeExportNames).toEqual(
            expect.arrayContaining([...requiredPublicFunctionNames]),
        );
        for (const publicFunctionName of runtimeExportNames) {
            expect(
                typeof publicApiRuntimeRecord[publicFunctionName],
                publicFunctionName,
            ).toBe('function');
        }
    });

    it('runs a no-WASM board-consistency smoke path', () => {
        expect(
            verifyBoardConsistency({
                ceremonyId: 'ceremony',
                boardPolicyHash: 'policy',
                expectedBoardPublicKeyHash: 'board-key',
                signedBoardHeads: [],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
    });
});
