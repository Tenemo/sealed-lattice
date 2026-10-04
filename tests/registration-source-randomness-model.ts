import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { operationSeedBytes } from '#tests/operation-seed-model.js';
import { byteAlignedSpongePermutations } from '#tests/proof-hash-work-model.js';
import { registrationSigningPublicKeyBytes } from '#tests/registration-enrollment-model.js';
import { compileRegistrationSetupBindingScreen } from '#tests/registration-setup-binding-model.js';
import { setupGaussianParameters } from '#tests/setup-randomness-model.js';
import { boundSparseSupportSampling } from '#tests/sparse-sampling-bound-model.js';

// One original enrollment's exact family inventory. Reconstructing a retained
// source repeats work on the same stream; it creates no new seed or salt.
// The sparse comparison cap is proof-only, never a runtime draw limit.
export const compileRegistrationSourceRandomness = (
    originalPollMaximumParticipants: number,
    optionCount: number,
) => {
    const inventory = compileRegistrationSetupBindingScreen(
        originalPollMaximumParticipants,
        optionCount,
    );
    const degree = fixedModulusBfvInputs.polynomialDegree;
    const sparse = boundSparseSupportSampling(
        degree,
        fixedModulusBfvInputs.secretSupportWeight,
    );
    const gaussianBytes = degree * (setupGaussianParameters.sampleBits / 8n);
    const minimumSourceOutputBytes = 4n * sparse.support + gaussianBytes;
    const comparisonMaximumSourceOutputBytes =
        sparse.maximumExaminedBytes + gaussianBytes;
    const bytes = (value: string) => BigInt(Buffer.byteLength(value, 'ascii'));
    const commonInputBytes =
        bytes('synthetic-full-setup-witness/1') + 4n + bytes('common-fhe-a-0');
    const families = inventory.fhe.map((family, index) => {
        const modulusBytes = BigInt(
            Math.ceil(family.modulus.toString(2).length / 8),
        );
        // Seven tuple items; the final seed is fixed bytes, with no inner
        // length. Only the ASCII domain and modulus have inner lengths.
        const sourceInputBytes =
            8n +
            7n * 6n +
            4n +
            bytes('sealed-lattice/fhe-source-randomness/v1') +
            registrationSigningPublicKeyBytes +
            2n * 64n +
            4n +
            modulusBytes +
            8n +
            operationSeedBytes;
        // Domain, owner, salt, poll, runtime, modulus, sampler width and the
        // complete variable-byte public coordinate. This is ordinary SHAKE,
        // without ProtocolHash's separate fixed 64-byte prefix.
        const commitmentInputBytes =
            8n +
            8n * 6n +
            4n +
            bytes('sealed-lattice/registered-fhe-key/v1') +
            registrationSigningPublicKeyBytes +
            64n +
            2n * 64n +
            4n +
            modulusBytes +
            8n +
            4n +
            family.publicCoordinateBytes;
        const commonOutputBytes = (degree * BigInt(family.sampleBits)) / 8n;
        return {
            index,
            modulusBytes,
            sampleBits: family.sampleBits,
            publicCoordinateBytes: family.publicCoordinateBytes,
            sourceInputBytes,
            minimumSourceOutputBytes,
            comparisonMaximumSourceOutputBytes,
            comparisonSourcePermutations: byteAlignedSpongePermutations(
                sourceInputBytes,
                comparisonMaximumSourceOutputBytes,
                136n,
            ),
            commitmentInputBytes,
            commitmentPermutations: byteAlignedSpongePermutations(
                commitmentInputBytes,
                64n,
                136n,
            ),
            commonInputBytes,
            commonOutputBytes,
            commonPermutations: byteAlignedSpongePermutations(
                commonInputBytes,
                commonOutputBytes,
                136n,
            ),
        };
    });
    return {
        originalPollMaximumParticipants,
        optionCount,
        families,
        sourceSeedCount: inventory.coordinateCount,
        freshSeedAndSaltBytes: inventory.privateSeedAndSaltPayloadBytes,
        gaussianSamples: inventory.coordinateCount * degree,
        sparseCalls: inventory.coordinateCount,
        sparseComparisonFailureNumerator:
            inventory.coordinateCount * sparse.numerator,
        sparseComparisonFailureDenominator: sparse.denominator,
        // These sum actual local work; repeated common stream inputs are
        // not distinct random-oracle queries or independent random matrices.
        comparisonHashPermutations: families.reduce(
            (sum, family) =>
                sum +
                family.comparisonSourcePermutations +
                family.commitmentPermutations +
                family.commonPermutations,
            0n,
        ),
    };
};
