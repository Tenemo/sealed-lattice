import { deriveProtocolHash } from '#packages/crypto/src/index';
import type {
    CollectiveBgvSetupContext,
    VssOpeningRandomByteSource,
} from '#packages/protocol/src/index';

// Collective BGV setup test suites derive every fixture value from a per-suite
// namespace so the deterministic protocol hashes stay isolated between suites.
// These shared factories keep a single definition of that derivation instead of
// repeating the same fixture-hash, deterministic-randomness, and setup-context
// boilerplate in every suite. Each factory is parameterized by the suite's
// fixture namespace, so the produced values are byte-identical to the previous
// per-suite copies.

export type SetupFixtureHash = (label: string) => string;

export const makeSetupFixtureHash =
    (fixtureNamespace: string): SetupFixtureHash =>
    (label) =>
        deriveProtocolHash('ActionContextHash', {
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
                        deriveProtocolHash('ActionContextHash', {
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

// The collective BGV setup context shared by the setup test suites. Every hash
// field is derived from the suite's own fixture hash, so distinct suites still
// produce distinct contexts while sharing one structural definition. A few
// suites seed the carry-aware relation hash from the shorter 'carry-aware'
// label, so that label is parameterized to keep every produced context
// byte-identical to its previous per-suite copy.
export const makeSetupContext = (
    fixtureHash: SetupFixtureHash,
    carryAwareVssShareRelationProfileLabel = 'carry-aware-vss-share-relation-profile',
): CollectiveBgvSetupContext => ({
    ceremonyId: 'ceremony-1',
    manifestHash: fixtureHash('manifest'),
    rosterHash: fixtureHash('roster'),
    setupProfileHash: fixtureHash('setup-profile'),
    qShareHash: fixtureHash('q-share'),
    carryAwareVssShareRelationProfileHash: fixtureHash(
        carryAwareVssShareRelationProfileLabel,
    ),
    commitmentProfileHash: fixtureHash('commitment-profile'),
    setupEpoch: 'setup-epoch-1',
});
