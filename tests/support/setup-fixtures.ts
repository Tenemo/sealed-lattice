import { deriveCanonicalObjectHash } from '#packages/crypto/src/index';
import type {
    CollectiveBgvSetupContext,
    VssOpeningRandomByteSource,
} from '#packages/protocol/src/index';

// Per-suite namespaces keep deterministic fixture hashes isolated.

export type SetupFixtureHash = (label: string) => string;

export const makeSetupFixtureHash =
    (fixtureNamespace: string): SetupFixtureHash =>
    (label) =>
        deriveCanonicalObjectHash({
            objectType: 'SetupFixtureHash',
            fixture: fixtureNamespace,
            label,
        });

export const makeVssOpeningRandomBytes =
    (fixtureNamespace: string) =>
    (seedLabel: string): VssOpeningRandomByteSource => {
        const textEncoder = new TextEncoder();
        let blockIndex = 0;
        let bufferedBytes = new Uint8Array(0);
        let bufferedOffset = 0;

        return (byteLength) => {
            const outputBytes = new Uint8Array(byteLength);
            let outputOffset = 0;
            while (outputOffset < byteLength) {
                if (bufferedOffset >= bufferedBytes.byteLength) {
                    bufferedBytes = textEncoder.encode(
                        deriveCanonicalObjectHash({
                            objectType: 'SetupFixtureHash',
                            fixture: fixtureNamespace,
                            seedLabel,
                            blockIndex,
                        }),
                    );
                    bufferedOffset = 0;
                    blockIndex += 1;
                }
                const copyLength = Math.min(
                    byteLength - outputOffset,
                    bufferedBytes.byteLength - bufferedOffset,
                );
                outputBytes.set(
                    bufferedBytes.subarray(
                        bufferedOffset,
                        bufferedOffset + copyLength,
                    ),
                    outputOffset,
                );
                bufferedOffset += copyLength;
                outputOffset += copyLength;
            }

            return outputBytes;
        };
    };

export const makeSetupContext = (
    fixtureHash: SetupFixtureHash,
    participantCount: number,
): CollectiveBgvSetupContext => ({
    ceremonyId: 'ceremony-1',
    manifestHash: fixtureHash('manifest'),
    rosterHash: fixtureHash('roster'),
    setupParametersHash: fixtureHash('setup-parameters'),
    setupEpoch: 'setup-epoch-1',
    participantCount,
});
