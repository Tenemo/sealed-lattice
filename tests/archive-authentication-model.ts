import { pureSignatureFrame } from '#tests/authentication-work-model.js';
import { byteAlignedSpongePermutations } from '#tests/proof-hash-work-model.js';
import { compilePublicArchiveResourceCensus } from '#tests/public-archive-resource-model.js';

// Per-call work bounds, not lifetime key or signing-query limits. The host signs
// every successful retain request, including a retry for an already stored root.
export const compileArchiveAuthenticationWork = (
    replicaCount: bigint = compilePublicArchiveResourceCensus().maximumReplicas,
) => {
    const maximumReplicas =
        compilePublicArchiveResourceCensus().maximumReplicas;
    if (replicaCount < 1n || replicaCount > maximumReplicas)
        throw new RangeError('Unsupported archive replica count.');
    const context = 'sealed-lattice/archive-retention/v1';
    const messageBytes = 64n;
    const frameBytes = BigInt(
        pureSignatureFrame(
            Buffer.from(context),
            new Uint8Array(Number(messageBytes)),
        ).byteLength,
    );
    const representativeInputBytes = 64n + frameBytes;
    return {
        context,
        messageBytes,
        contextBytes: BigInt(Buffer.byteLength(context)),
        frameBytes,
        representativeInputBytes,
        representativePermutations: byteAlignedSpongePermutations(
            representativeInputBytes,
            64n,
            136n,
        ),
        replicaCount,
        signaturesPerSuccessfulRetentionRequest: 1n,
        maximumSdkRetentionRequestsPerPublish: replicaCount,
        maximumAcknowledgementBatchesPerPublish: replicaCount,
        maximumSignatureVerificationsPerPublish:
            (replicaCount * (replicaCount + 1n)) / 2n,
        maximumSignatureVerificationsPerDirectCall: maximumReplicas,
    };
};
