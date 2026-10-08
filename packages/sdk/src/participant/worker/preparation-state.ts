import {
    concatenate,
    encodeText,
    equalBytes,
    readUnsigned32,
    unsigned32,
} from './bytes.js';
import type { ParticipantProfile } from './runtime-bounds.js';
import { purposeBit, signingPurpose } from './signing-purpose.js';

export type PreparationSignature = Readonly<
    | { stage: 'intent'; body: Uint8Array }
    | { stage: 'signed'; body: Uint8Array; signature: Uint8Array }
>;

export type PreparationEndorsement = PreparationSignature &
    Readonly<{
        selection: Readonly<{ body: Uint8Array; signature: Uint8Array }>;
        reference: Uint8Array;
    }>;

// Each authority has its own durable intent. An unfinished own offer does
// not prevent a participant from endorsing or accepting a selected setup.
export type PreparationState = Readonly<{
    contribution?: Uint8Array;
    selection?: PreparationSignature;
    endorsement?: PreparationEndorsement;
}>;

const signatureTail = (state: PreparationSignature) =>
    state.stage === 'intent' ? new Uint8Array() : state.signature;

export const encodePreparationState = (state: PreparationState) => {
    const selection = state.selection;
    const endorsement = state.endorsement;
    const fields = [
        state.contribution ?? new Uint8Array(),
        selection === undefined
            ? new Uint8Array()
            : concatenate(
                  new Uint8Array([selection.stage === 'intent' ? 1 : 2]),
                  selection.body,
                  signatureTail(selection),
              ),
        endorsement === undefined
            ? new Uint8Array()
            : concatenate(
                  new Uint8Array([endorsement.stage === 'intent' ? 1 : 2]),
                  endorsement.selection.body,
                  endorsement.selection.signature,
                  endorsement.reference,
                  endorsement.body,
                  signatureTail(endorsement),
              ),
    ];
    return concatenate(
        encodeText('PRE2'),
        ...fields.flatMap((bytes) => [unsigned32(bytes.length), bytes]),
    );
};

const splitPreparation = (bytes: Uint8Array) => {
    if (!equalBytes(bytes.subarray(0, 4), encodeText('PRE2')))
        throw new Error('Invalid preparation journal.');
    let offset = 4;
    const fields: Uint8Array[] = [];
    for (let index = 0; index < 3; index++) {
        if (bytes.length - offset < 4)
            throw new Error('Truncated preparation journal.');
        const length = readUnsigned32(bytes, offset);
        offset += 4;
        if (length > bytes.length - offset)
            throw new Error('Truncated preparation authority.');
        fields.push(bytes.slice(offset, offset + length));
        offset += length;
    }
    if (offset !== bytes.length)
        throw new Error('Preparation journal has trailing bytes.');
    return fields;
};

const decodeSignature = (
    bytes: Uint8Array,
    bodyOffset: number,
    bodyLength: number,
    signatureBytes: number,
): PreparationSignature => {
    const stage = bytes[0];
    if (
        (stage !== 1 && stage !== 2) ||
        bytes.length !==
            bodyOffset + bodyLength + (stage === 1 ? 0 : signatureBytes)
    )
        throw new Error('Invalid preparation signing intent.');
    const body = bytes.slice(bodyOffset, bodyOffset + bodyLength);
    const tail = bytes.slice(bodyOffset + bodyLength);
    return stage === 1
        ? { stage: 'intent', body }
        : { stage: 'signed', body, signature: tail };
};

export const decodePreparationState = (
    bytes: Uint8Array,
    profile: ParticipantProfile,
): PreparationState => {
    const [contribution, selection, endorsement] = splitPreparation(bytes);
    const {
        selectionBodyBytes,
        endorsementBodyBytes,
        selectionReferenceBytes,
    } = profile.preparation;
    const signatureBytes = profile.registration.signatureBytes;
    const selectionEnd = 1 + selectionBodyBytes;
    const signatureEnd = selectionEnd + signatureBytes;
    const referenceEnd = signatureEnd + selectionReferenceBytes;
    return {
        ...(contribution.length === 0 ? {} : { contribution }),
        ...(selection.length === 0
            ? {}
            : {
                  selection: decodeSignature(
                      selection,
                      1,
                      selectionBodyBytes,
                      signatureBytes,
                  ),
              }),
        ...(endorsement.length === 0
            ? {}
            : {
                  endorsement: {
                      ...decodeSignature(
                          endorsement,
                          referenceEnd,
                          endorsementBodyBytes,
                          signatureBytes,
                      ),
                      selection: {
                          body: endorsement.slice(1, selectionEnd),
                          signature: endorsement.slice(
                              selectionEnd,
                              signatureEnd,
                          ),
                      },
                      reference: endorsement.slice(signatureEnd, referenceEnd),
                  },
              }),
    };
};

// Restoring the credential precedes profile decoding. These authenticated
// structural phases determine which one-shot purposes are still available;
// the complete canonical shape is checked before any operation can sign.
export const unusedPreparationPurposes = (bytes: Uint8Array) => {
    const [contribution, selection, endorsement] = splitPreparation(bytes);
    let mask = 0;
    if (contribution.length === 0) mask |= purposeBit(signingPurpose.offer);
    else {
        const phase = contribution[4];
        if (
            !equalBytes(contribution.subarray(0, 4), encodeText('PCS5')) ||
            phase === undefined ||
            phase < 4 ||
            phase > 9
        )
            throw new Error('Invalid retained offer phase.');
        if (phase < 9) mask |= purposeBit(signingPurpose.offer);
    }
    for (const [purpose, field] of [
        [signingPurpose.selectionProposal, selection],
        [signingPurpose.selectionEndorsement, endorsement],
    ] as const) {
        if (field.length === 0 || field[0] === 1) mask |= purposeBit(purpose);
        else if (field[0] !== 2)
            throw new Error('Invalid retained preparation signature phase.');
    }
    return mask;
};
