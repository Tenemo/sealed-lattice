import { createHash } from 'node:crypto';

import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileSetupSelectionCensus } from '#tests/setup-selection-model.js';

export type SelectedContributionModel = Readonly<{
    position: number;
    bodyIdentity: string;
}>;

const unsigned = (value: number, width: number) => {
    const bytes = Buffer.alloc(width);
    bytes.writeUIntLE(value, 0, width);
    return bytes;
};
const variable = (bytes: Buffer) =>
    Buffer.concat([unsigned(bytes.length, 4), bytes]);
const item = (type: number, bytes: Buffer) =>
    Buffer.concat([unsigned(type, 2), unsigned(bytes.length, 4), bytes]);
const tuple = (items: Buffer[]) =>
    Buffer.concat([
        unsigned(1, 2),
        unsigned(1, 2),
        unsigned(items.length, 4),
        ...items,
    ]);
const ascii = (text: string) => item(2, variable(Buffer.from(text, 'ascii')));
const hash = (hexadecimal: string) => {
    if (!/^[0-9a-f]{128}$/u.test(hexadecimal))
        throw new RangeError('Noncanonical model identity.');
    return item(6, Buffer.from(hexadecimal, 'hex'));
};

// Independent canonical wire arithmetic. This model hashes and parses no
// proof and issues no verified capability or signature verdict.
export const encodeSetupSelectionModel = (
    participants: number,
    rosterIdentity: string,
    selected: readonly SelectedContributionModel[],
) => {
    const profile = compileSetupSelectionCensus(participants);
    if (
        selected.length !== profile.selectedCount ||
        selected.some(
            (entry, index) =>
                !Number.isSafeInteger(entry.position) ||
                entry.position < 0 ||
                entry.position >= profile.eligibleCount ||
                (index > 0 && selected[index - 1].position >= entry.position),
        )
    )
        throw new RangeError('Noncanonical selected contribution inventory.');
    const entries = selected.map(({ position, bodyIdentity }) => {
        hash(bodyIdentity);
        return Buffer.concat([
            unsigned(position, 2),
            Buffer.from(bodyIdentity, 'hex'),
        ]);
    });
    return tuple([
        ascii('sealed-lattice/setup-selection/v1'),
        hash(rosterIdentity),
        item(
            1,
            variable(Buffer.concat([unsigned(selected.length, 4), ...entries])),
        ),
    ]);
};

export const setupSelectionIdentityModel = (
    participants: number,
    rosterIdentity: string,
    selected: readonly SelectedContributionModel[],
) =>
    createHash('shake256', { outputLength: 64 })
        .update(
            tuple([
                ascii('sealed-lattice/setup-selection-identity/v1'),
                item(
                    1,
                    variable(
                        encodeSetupSelectionModel(
                            participants,
                            rosterIdentity,
                            selected,
                        ),
                    ),
                ),
            ]),
        )
        .digest('hex');

export const encodeSetupCertificateModel = (
    participants: number,
    rosterIdentity: string,
    selected: readonly SelectedContributionModel[],
    organizerSignature: Buffer,
    endorsements: readonly Readonly<{ position: number; signature: Buffer }>[],
) => {
    const census = compileSetupSelectionWireCensus(participants);
    if (
        BigInt(organizerSignature.length) !== census.signatureBytes ||
        endorsements.length !== census.quorum ||
        endorsements.some(
            (entry, index) =>
                !Number.isSafeInteger(entry.position) ||
                entry.position < 0 ||
                entry.position >= participants ||
                BigInt(entry.signature.length) !== census.signatureBytes ||
                (index > 0 &&
                    endorsements[index - 1].position >= entry.position),
        )
    )
        throw new RangeError('Noncanonical setup certificate carrier.');
    const body = encodeSetupSelectionModel(
        participants,
        rosterIdentity,
        selected,
    );
    return Buffer.concat([
        Buffer.from('SSC1'),
        unsigned(body.length, 4),
        body,
        organizerSignature,
        ...endorsements.map(({ position, signature }) =>
            Buffer.concat([unsigned(position, 2), signature]),
        ),
    ]);
};

export const compileSetupSelectionWireCensus = (participants: number) => {
    const profile = compileSetupSelectionCensus(participants);
    const signatureBytes = compileRegistrationEnrollmentCensus().signatureBytes;
    const text = (value: string) => BigInt(Buffer.byteLength(value, 'ascii'));
    const offerEnvelopeBytes =
        8n +
        5n * 6n +
        4n +
        text('sealed-lattice/contribution-offer/v1') +
        64n +
        2n +
        8n +
        64n;
    const selectionBodyBytes =
        8n +
        3n * 6n +
        4n +
        text('sealed-lattice/setup-selection/v1') +
        64n +
        4n +
        4n +
        BigInt(profile.selectedCount) * (2n + 64n);
    const endorsementBodyBytes =
        8n +
        3n * 6n +
        4n +
        text('sealed-lattice/setup-selection-endorsement/v1') +
        64n +
        2n;
    return {
        ...profile,
        signatureBytes,
        offerEnvelopeBytes,
        offerPacketBytes: 4n + offerEnvelopeBytes + signatureBytes,
        selectionBodyBytes,
        signedSelectionPacketBytes: 4n + selectionBodyBytes + signatureBytes,
        endorsementBodyBytes,
        endorsementPacketBytes: 2n + 64n + signatureBytes,
        certificateBytes:
            4n +
            4n +
            selectionBodyBytes +
            signatureBytes +
            BigInt(profile.quorum) * (2n + signatureBytes),
        allEligibleOfferPacketBytes:
            BigInt(profile.eligibleCount) *
            (4n + offerEnvelopeBytes + signatureBytes),
        quorumEndorsementPacketBytes:
            BigInt(profile.quorum) * (2n + 64n + signatureBytes),
        // Ordinary body identity: domain and variable-byte body, no sender,
        // whole-body salt, role or predecessor copied into this hash input.
        bodyHashPrefixBytes:
            8n +
            2n * 6n +
            4n +
            text('sealed-lattice/contribution-body/v1') +
            4n,
    };
};
