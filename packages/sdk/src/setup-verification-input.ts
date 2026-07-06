import { createSetupPackageVerificationInput } from '@sealed-lattice/protocol';
import type {
    EvaluationKeyShareComponentMaterialChunkStream,
    SetupPackageVerificationInputSource,
    TransportedEvaluationKeyShareComponentMaterialSet,
    TransportedEvaluationKeyShareProofMaterialSet,
    TransportedPublicKeyShareProofMaterialSet,
    TransportedSameSecretBridgeProofMaterialSet,
    TransportedSameSecretProofMaterialSet,
    TransportedVssShareLinkageProofMaterialSet,
    VerifiedSetupProofMaterial,
    VerifiedSetupProofMaterialSet,
} from '@sealed-lattice/protocol';
import type { TranscriptCoreKernel } from '@sealed-lattice/wasm';

import type { VerifySetupPackageInput } from './index.js';

type JsonRecord = Record<string, unknown>;

type SetupProofMaterialTransportFieldName =
    | 'transportedSameSecretProofMaterial'
    | 'transportedPublicKeyShareProofMaterial'
    | 'transportedVssShareLinkageProofMaterial'
    | 'transportedSameSecretBridgeProofMaterial'
    | 'transportedEvaluationKeyShareProofMaterial';

type SetupProofMaterialTransportSet =
    | TransportedSameSecretProofMaterialSet
    | TransportedPublicKeyShareProofMaterialSet
    | TransportedVssShareLinkageProofMaterialSet
    | TransportedSameSecretBridgeProofMaterialSet
    | TransportedEvaluationKeyShareProofMaterialSet;

type SetupProofMaterialChunk = Readonly<{
    readonly chunkIndex: number;
    readonly bytesHex: string;
}>;

const setupProofMaterialTransportFieldNames = [
    'transportedSameSecretProofMaterial',
    'transportedPublicKeyShareProofMaterial',
    'transportedVssShareLinkageProofMaterial',
    'transportedSameSecretBridgeProofMaterial',
    'transportedEvaluationKeyShareProofMaterial',
] as const satisfies readonly SetupProofMaterialTransportFieldName[];

let setupProofMaterialVerificationSequence = 0;

// Verification ids are process-local kernel stream handles, not security bindings; the cryptographic binding is the full proof material root.
const setupProofMaterialVerificationId = (
    fieldName: SetupProofMaterialTransportFieldName,
    materialIndex: number,
    proofMaterial: JsonRecord,
): string => {
    setupProofMaterialVerificationSequence += 1;
    const proofMaterialRoot =
        typeof proofMaterial.proofMaterialRoot === 'string'
            ? proofMaterial.proofMaterialRoot.slice(0, 24)
            : 'unbound';

    return [
        'sdk-proof-material',
        String(setupProofMaterialVerificationSequence),
        fieldName,
        String(materialIndex),
        proofMaterialRoot,
    ].join('-');
};

const setupProofMaterialReference = (proofMaterial: JsonRecord): JsonRecord => {
    const { chunks: omittedChunks, ...reference } = proofMaterial;
    void omittedChunks;

    return reference;
};

const setupProofMaterialChunks = (
    proofMaterial: unknown,
): readonly SetupProofMaterialChunk[] | undefined => {
    if (
        proofMaterial === null ||
        typeof proofMaterial !== 'object' ||
        !Object.prototype.hasOwnProperty.call(proofMaterial, 'chunks')
    ) {
        return undefined;
    }

    const chunks = (proofMaterial as JsonRecord).chunks;

    return Array.isArray(chunks)
        ? (chunks as readonly SetupProofMaterialChunk[])
        : undefined;
};

const streamSetupProofMaterialSet = (
    kernel: TranscriptCoreKernel,
    fieldName: SetupProofMaterialTransportFieldName,
    materialSet: SetupProofMaterialTransportSet | undefined,
): readonly VerifiedSetupProofMaterial[] => {
    if (
        materialSet === undefined ||
        !Array.isArray(materialSet.proofMaterials)
    ) {
        return [];
    }

    const verifiedMaterials: VerifiedSetupProofMaterial[] = [];
    materialSet.proofMaterials.forEach((proofMaterialValue, materialIndex) => {
        const chunks = setupProofMaterialChunks(proofMaterialValue);
        if (chunks === undefined) {
            return;
        }
        const proofMaterial = proofMaterialValue as JsonRecord;
        const proofMaterialReference =
            setupProofMaterialReference(proofMaterial);
        const verificationId = setupProofMaterialVerificationId(
            fieldName,
            materialIndex,
            proofMaterial,
        );
        kernel.beginSetupProofMaterialTransportStream({
            verificationId,
            transportedSetupProofMaterial: proofMaterialReference,
        });
        chunks.forEach((chunk) => {
            kernel.absorbSetupProofMaterialTransportStreamChunk({
                verificationId,
                chunkIndex: chunk.chunkIndex,
                bytesHex: chunk.bytesHex,
            });
        });
        const verification = kernel.finishSetupProofMaterialTransportStream({
            verificationId,
        });
        verifiedMaterials.push(
            verification.verifiedSetupProofMaterial as VerifiedSetupProofMaterial,
        );
    });

    return verifiedMaterials;
};

type JsonRecordWithRoot = JsonRecord &
    Readonly<{ readonly keySwitchComponentMaterialRoot?: unknown }>;

// Verification ids are process-local kernel stream handles, not security bindings; the cryptographic binding is the component material root.
const evaluationKeyShareComponentMaterialVerificationId = (
    streamIndex: number,
    keySwitchComponentMaterialRoot: string,
): string =>
    [
        'sdk-evaluation-key-component-material',
        String(streamIndex),
        keySwitchComponentMaterialRoot.slice(0, 24),
    ].join('-');

// Streams each transported evaluation-key component material through the
// file-backed component material transport so the kernel holds a stream-verified
// handle keyed by keySwitchComponentMaterialRoot before the terminal setup
// package verification runs. This mirrors the setup proof material streaming
// above: begin the stream with the chunkless component material reference,
// absorb each chunk, then finish. The terminal accepted-setup verifier reads the
// verified handle transiently, so the transported component material carries only
// the chunkless manifest reference and never the raw chunk bytes.
const streamEvaluationKeyShareComponentMaterial = (
    kernel: TranscriptCoreKernel,
    transportedMaterialSet:
        | TransportedEvaluationKeyShareComponentMaterialSet
        | undefined,
    chunkStreams:
        | readonly EvaluationKeyShareComponentMaterialChunkStream[]
        | undefined,
): void => {
    if (
        transportedMaterialSet === undefined ||
        chunkStreams === undefined ||
        chunkStreams.length === 0
    ) {
        return;
    }
    if (!Array.isArray(transportedMaterialSet.componentMaterials)) {
        throw new TypeError(
            'transportedEvaluationKeyShareComponentMaterial.componentMaterials must be an array to stream component material.',
        );
    }
    const componentMaterialReferenceByRoot = new Map<
        string,
        JsonRecordWithRoot
    >();
    transportedMaterialSet.componentMaterials.forEach(
        (componentMaterialValue, componentMaterialIndex) => {
            const componentMaterial =
                componentMaterialValue as JsonRecordWithRoot;
            const keySwitchComponentMaterialRoot =
                componentMaterial.keySwitchComponentMaterialRoot;
            if (typeof keySwitchComponentMaterialRoot !== 'string') {
                throw new TypeError(
                    `transportedEvaluationKeyShareComponentMaterial.componentMaterials.${String(
                        componentMaterialIndex,
                    )}.keySwitchComponentMaterialRoot must be a string.`,
                );
            }
            componentMaterialReferenceByRoot.set(
                keySwitchComponentMaterialRoot,
                componentMaterial,
            );
        },
    );

    chunkStreams.forEach((chunkStream, streamIndex) => {
        const componentMaterialReference =
            componentMaterialReferenceByRoot.get(
                chunkStream.keySwitchComponentMaterialRoot,
            );
        if (componentMaterialReference === undefined) {
            throw new Error(
                'evaluationKeyShareComponentMaterialChunkStreams references a keySwitchComponentMaterialRoot without a transported component material reference.',
            );
        }
        const verificationId =
            evaluationKeyShareComponentMaterialVerificationId(
                streamIndex,
                chunkStream.keySwitchComponentMaterialRoot,
            );
        kernel.beginEvaluationKeyShareComponentMaterialTransportStream({
            verificationId,
            transportedEvaluationKeyShareComponentMaterial:
                componentMaterialReference,
        });
        chunkStream.chunks.forEach((chunk) => {
            kernel.absorbEvaluationKeyShareComponentMaterialTransportStreamChunk(
                {
                    verificationId,
                    chunkIndex: chunk.chunkIndex,
                    bytesHex: chunk.bytesHex,
                },
            );
        });
        kernel.finishEvaluationKeyShareComponentMaterialTransportStream({
            verificationId,
        });
    });
};

const setupPackageVerificationInput = (
    input: VerifySetupPackageInput,
): VerifySetupPackageInput => {
    const verificationInput = createSetupPackageVerificationInput(
        input as unknown as SetupPackageVerificationInputSource,
    ) as VerifySetupPackageInput;

    return input.expectedSetupPackageHash === undefined
        ? verificationInput
        : {
              ...verificationInput,
              expectedSetupPackageHash: input.expectedSetupPackageHash,
          };
};

export const prepareSetupPackageVerificationInputForKernel = (
    kernel: TranscriptCoreKernel,
    input: VerifySetupPackageInput,
): VerifySetupPackageInput => {
    // The evaluation-key component material streams independently of the setup
    // proof material and of any caller-supplied verified proof handles, so it is
    // streamed first regardless of which proof material branch is taken. The
    // chunkless component material reference stays in
    // transportedEvaluationKeyShareComponentMaterial; only the raw chunk bytes
    // are consumed here.
    streamEvaluationKeyShareComponentMaterial(
        kernel,
        input.transportedEvaluationKeyShareComponentMaterial,
        input.evaluationKeyShareComponentMaterialChunkStreams,
    );

    if (input.verifiedSetupProofMaterials !== undefined) {
        return setupPackageVerificationInput(input);
    }

    const verifiedMaterials = setupProofMaterialTransportFieldNames.flatMap(
        (fieldName) =>
            streamSetupProofMaterialSet(kernel, fieldName, input[fieldName]),
    );
    if (verifiedMaterials.length === 0) {
        // No streamed proof-material handles to thread; the public-only
        // verification input is still rebuilt so the out-of-band component
        // material chunk streams are dropped before the kernel verify.
        return setupPackageVerificationInput(input);
    }

    const verifiedSetupProofMaterials = {
        objectType: 'VerifiedSetupProofMaterialSet',
        proofMaterials: verifiedMaterials,
    } as const satisfies VerifiedSetupProofMaterialSet;

    return setupPackageVerificationInput({
        ...input,
        verifiedSetupProofMaterials,
    });
};
