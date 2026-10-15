import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { sourceCiphertextBytes } from '#tests/encrypted-registration-source-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { byteAlignedSpongePermutations } from '#tests/proof-hash-work-model.js';
import { compileRegistrationSetupBindingScreen } from '#tests/registration-setup-binding-model.js';
import { setupGaussianParameters } from '#tests/setup-randomness-model.js';
import { boundSparseSupportSampling } from '#tests/sparse-sampling-bound-model.js';

const registrationSourceSeedBytes = 64n;
export const sourceCommonSampleBits = 576n;

// Each family has one original seed and two disjoint purpose streams.
// Regeneration repeats those streams; it creates no new original source.
export const compileRegistrationSourceRandomness = (
    originalPollMaximumParticipants: number,
    optionCount: number,
) => {
    const inventory = compileRegistrationSetupBindingScreen(
        originalPollMaximumParticipants,
        optionCount,
    );
    const degree = fixedModulusBfvInputs.polynomialDegree;
    const auxiliary = auxiliaryInputEncryptionParameters;
    const sourceSparse = boundSparseSupportSampling(
        degree,
        fixedModulusBfvInputs.secretSupportWeight,
    );
    const encryptionSparse = boundSparseSupportSampling(
        auxiliary.degree,
        auxiliary.support,
    );
    const errorBytes = degree * (setupGaussianParameters.sampleBits / 8n);
    const sourceCommonCalls = (4n * degree) / auxiliary.degree;
    const sourceCommonInputBytes =
        BigInt(Buffer.byteLength('sealed-lattice/source-common/v1')) + 5n;
    const sourceCommonOutputBytes =
        (auxiliary.degree * sourceCommonSampleBits) / 8n;
    const families = inventory.fhe.map((family, index) => {
        const modulusBytes = BigInt(
            Math.ceil(family.modulus.toString(2).length / 8),
        );
        const sourceInputBytes =
            BigInt(Buffer.byteLength('sealed-lattice/source-private/v1')) +
            1n +
            registrationSourceSeedBytes +
            128n +
            4n +
            2n +
            modulusBytes +
            4n;
        const minimumSourceOutputBytes = 4n * sourceSparse.support + errorBytes;
        const comparisonMaximumSourceOutputBytes =
            sourceSparse.maximumExaminedBytes + errorBytes;
        const minimumEncryptionOutputBytes =
            4n * encryptionSparse.support + 4n * errorBytes;
        const comparisonMaximumEncryptionOutputBytes =
            encryptionSparse.maximumExaminedBytes + 4n * errorBytes;
        const bindingInputBytes =
            64n +
            BigInt(Buffer.byteLength('sealed-lattice/registered-source/v1')) +
            128n +
            4n +
            2n +
            modulusBytes +
            4n +
            8n +
            sourceCiphertextBytes;
        const comparisonSourcePermutations = byteAlignedSpongePermutations(
            sourceInputBytes,
            comparisonMaximumSourceOutputBytes,
            136n,
        );
        const comparisonEncryptionPermutations = byteAlignedSpongePermutations(
            sourceInputBytes,
            comparisonMaximumEncryptionOutputBytes,
            136n,
        );
        const bindingPermutations = byteAlignedSpongePermutations(
            bindingInputBytes,
            64n,
            136n,
        );
        const commonPermutations =
            sourceCommonCalls *
            byteAlignedSpongePermutations(
                sourceCommonInputBytes,
                sourceCommonOutputBytes,
                136n,
            );
        return {
            index,
            modulusBytes,
            sampleBits: family.sampleBits,
            sourceInputBytes,
            minimumSourceOutputBytes,
            comparisonMaximumSourceOutputBytes,
            minimumEncryptionOutputBytes,
            comparisonMaximumEncryptionOutputBytes,
            bindingInputBytes,
            comparisonSourcePermutations,
            comparisonEncryptionPermutations,
            bindingPermutations,
            sourceCommonCalls,
            sourceCommonInputBytes,
            sourceCommonOutputBytes,
            commonPermutations,
        };
    });
    return {
        originalPollMaximumParticipants,
        optionCount,
        families,
        sourceSeedCount: inventory.coordinateCount,
        freshSeedBytes: inventory.coordinateCount * registrationSourceSeedBytes,
        gaussianSamples: 5n * inventory.coordinateCount * degree,
        sparseCalls: 2n * inventory.coordinateCount,
        sparseComparisons: [sourceSparse, encryptionSparse].map((sampler) => ({
            ...sampler,
            calls: inventory.coordinateCount,
        })),
        comparisonHashPermutations: families.reduce(
            (sum, family) =>
                sum +
                family.comparisonSourcePermutations +
                family.comparisonEncryptionPermutations +
                family.bindingPermutations +
                family.commonPermutations,
            0n,
        ),
        sourceCiphertextSamples: (4n * degree) / auxiliary.degree,
        sharedAuxiliaryKeySamples: (2n * degree) / auxiliary.degree + 1n,
    };
};
