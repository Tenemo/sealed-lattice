import assert from 'node:assert/strict';

import {
    labelledHashExtractionWork,
    sourceCoordinateDecodingWork,
} from '#tests/compressed-oracle-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { operationSeedBytes } from '#tests/operation-seed-model.js';
import { byteAlignedSpongePermutations } from '#tests/proof-hash-work-model.js';
import { registrationSigningPublicKeyBytes } from '#tests/registration-enrollment-model.js';
import { compileRegistrationSetupBindingScreen } from '#tests/registration-setup-binding-model.js';
import { registrationSourceMask } from '#tests/registration-source-domain-model.js';
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
            6n * 6n +
            4n +
            bytes('sealed-lattice/fhe-source-randomness/v2') +
            registrationSigningPublicKeyBytes +
            64n +
            4n +
            modulusBytes +
            8n +
            operationSeedBytes;
        // Domain, owner, salt, poll, modulus, sampler width and the complete
        // variable-byte public coordinate. This is ordinary SHAKE,
        // without ProtocolHash's separate fixed 64-byte prefix.
        const commitmentInputBytes =
            8n +
            7n * 6n +
            4n +
            bytes('sealed-lattice/registered-fhe-key/v2') +
            registrationSigningPublicKeyBytes +
            64n +
            64n +
            4n +
            modulusBytes +
            8n +
            4n +
            family.publicCoordinateBytes;
        const commonOutputBytes = (degree * BigInt(family.sampleBits)) / 8n;
        const sourceMask = registrationSourceMask(
            new Uint8Array(Number(registrationSigningPublicKeyBytes)),
            Uint8Array.from({ length: Number(modulusBytes) }, (_, offset) =>
                Number((family.modulus >> BigInt(8 * offset)) & 255n),
            ),
            BigInt(family.sampleBits),
            Number(degree),
        );
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
            commitmentMaskRawBits: sourceMask.comparedRawBits,
            commitmentMaskCellBits: sourceMask.comparedCellBits,
            commitmentInputCellBits: sourceMask.inputClassUpper + 1n,
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

// The first output component has the complete 512-bit commitment prefix.
// fullValueQueries is the caller's actual component-capacity bound, including
// every nested wrapper. The post-extraction decoder separately checks the
// context and coordinate and retains their canonical bytes. Query simulation,
// cache indexing and the DFMS disturbance/mismatch terms remain separate.
export const compileRegistrationSourceExtractionWork = (
    originalPollMaximumParticipants: number,
    optionCount: number,
    fullValueQueries: bigint,
    extractionRequests: bigint,
) => {
    assert.ok(fullValueQueries >= 0n && extractionRequests >= 0n);
    const inventory = compileRegistrationSourceRandomness(
        originalPollMaximumParticipants,
        optionCount,
    );
    const families = inventory.families.map((family) => {
        const selection = labelledHashExtractionWork(
            fullValueQueries,
            family.commitmentInputCellBits,
            512n,
            family.commitmentMaskCellBits,
            512n,
        );
        // Copy the classical target into clean input wires and erase that
        // copy afterward. Static zero bits only make this bound smaller.
        const targetPreparationGates =
            2n * (family.commitmentMaskCellBits + 512n);
        const coordinateDecodingGates = sourceCoordinateDecodingWork(
            fixedModulusBfvInputs.polynomialDegree,
            8n * family.modulusBytes,
        ).decodingGates;
        return {
            family: family.index,
            inputCellBits: family.commitmentInputCellBits,
            comparedInputBits: family.commitmentMaskCellBits,
            selectionGates: selection.extractionGates,
            targetPreparationGates,
            preparedSelectionGates:
                selection.extractionGates + targetPreparationGates,
            coordinateDecodingGates,
            preparedSelectionAndDecodingGates:
                selection.extractionGates +
                targetPreparationGates +
                coordinateDecodingGates,
        };
    });
    const maximumGatesPerRequest = families.reduce(
        (maximum, family) =>
            family.preparedSelectionGates > maximum
                ? family.preparedSelectionGates
                : maximum,
        0n,
    );
    const maximumDecodedGatesPerRequest = families.reduce(
        (maximum, family) =>
            family.preparedSelectionAndDecodingGates > maximum
                ? family.preparedSelectionAndDecodingGates
                : maximum,
        0n,
    );
    return {
        families,
        maximumPreparedSelectionGates:
            extractionRequests * maximumGatesPerRequest,
        maximumPreparedSelectionAndDecodingGates:
            extractionRequests * maximumDecodedGatesPerRequest,
    };
};
