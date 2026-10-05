import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileCloseWireCensus } from '#tests/close-wire-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSetupSelectionWireCensus } from '#tests/setup-selection-wire-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';
import { compileTargetSigningStateCensus } from '#tests/target-signing-state-model.js';

// Independently maintained wire operands: RCM1/u16 count, u16 name length,
// ASCII name, u64 payload length and one 16-byte locator per fixed chunk.
const candidateTransportParameters = {
    chunkBytes: 1_048_576n,
    manifestBytes: 1_048_576n,
    maximumFileBytes: 4_294_967_291n,
    maximumFiles: 256n,
    nameBytes: 160n,
    keyBytes: 256n,
    identifierBytes: 16n,
    pageEntries: 64n,
} as const;

type File = Readonly<{
    name: string;
    bytes: bigint;
    referenceManifestBytes?: bigint;
}>;
const chunks = (bytes: bigint) =>
    (bytes + candidateTransportParameters.chunkBytes - 1n) /
    candidateTransportParameters.chunkBytes;
const maximum = (values: readonly bigint[]) =>
    values.reduce((largest, value) => (value > largest ? value : largest), 0n);

const compileCandidatePublication = (
    key: string,
    files: readonly File[],
    readbackEntries = 1n,
) => {
    const p = candidateTransportParameters;
    if (
        files.length < 1 ||
        BigInt(files.length) > p.maximumFiles ||
        BigInt(Buffer.byteLength(key)) > p.keyBytes ||
        new Set(files.map((file) => file.name)).size !== files.length
    )
        throw new RangeError('Candidate inventory exceeds its framing.');
    let payloadBytes = 0n,
        uploadedBytes = 0n,
        uploadChunks = 0n,
        referencedChunks = 0n,
        referenceMetadataBytes = 0n,
        referenceFiles = 0n;
    let manifestBytes = 4n + 2n;
    for (const file of files) {
        const name = BigInt(Buffer.byteLength(file.name));
        if (
            file.bytes < 0n ||
            file.bytes > p.maximumFileBytes ||
            name > p.nameBytes
        )
            throw new RangeError('Candidate file exceeds its framing.');
        const count = chunks(file.bytes);
        manifestBytes += 2n + name + 8n + p.identifierBytes * count;
        payloadBytes += file.bytes;
        if (file.referenceManifestBytes === undefined) {
            uploadedBytes += file.bytes;
            uploadChunks += count;
        } else {
            referencedChunks += count;
            referenceFiles++;
            // One clean original ballot candidate at this source key.
            referenceMetadataBytes +=
                8n + 4n + p.identifierBytes + file.referenceManifestBytes;
        }
    }
    if (manifestBytes > p.manifestBytes)
        throw new RangeError('Candidate manifest exceeds its framing.');
    const receiptBytes =
        uploadChunks * p.identifierBytes + p.identifierBytes + 8n;
    const discoveryReadbackBytes = 12n + p.identifierBytes * readbackEntries;
    return {
        key,
        files: BigInt(files.length),
        payloadBytes,
        manifestBytes,
        uploadChunks,
        referencedChunks,
        referenceMetadataBytes,
        uploadedPayloadBytes: uploadedBytes + manifestBytes,
        readbackPayloadBytes:
            payloadBytes +
            manifestBytes +
            referenceMetadataBytes +
            discoveryReadbackBytes,
        receiptBytes,
        receivedPayloadBytes:
            payloadBytes +
            manifestBytes +
            referenceMetadataBytes +
            receiptBytes +
            discoveryReadbackBytes,
        // Chunk bodies, manifest, stored logical key and discovery entry.
        // Filesystem allocation/index/journal overhead remains separate.
        storedPayloadBytes:
            uploadedBytes +
            manifestBytes +
            BigInt(Buffer.byteLength(key)) +
            p.identifierBytes,
        requests:
            2n * uploadChunks + referencedChunks + 2n * referenceFiles + 3n,
    };
};

// The current clean ordinary schedule, including repeated publication and
// all response/closure references. Each reference is read and byte-compared
// against authenticated custody before it is advertised. Unavailable copies,
// corrupt candidates and arbitrary restarts have no finite lifetime bound.
export const compileCandidatePublicationCensus = (
    profile: SupportedProfile,
    offers = profile.setupContributorCount,
) => {
    const n = profile.participantCount;
    const registration = compileRegistrationEnrollmentCensus();
    const key = compileRegistrationKeyRelationCensus();
    const roster = compileRosterProposalCensus(n);
    const offer = compileContributionBodyCensus(profile);
    const selection = compileSetupSelectionWireCensus(n);
    const ballot = compileBallotBodyCensus(profile);
    const close = compileCloseWireCensus(profile);
    const release = compileParticipantReleaseCustody(profile);
    const target = compileTargetSigningStateCensus();
    if (
        !Number.isSafeInteger(offers) ||
        offers < profile.setupContributorCount ||
        offers > selection.eligibleCount
    )
        throw new RangeError('Invalid offer population.');
    const identity = (position: number) =>
        position.toString(16).padStart(128, '0');
    const file = (name: string, bytes: bigint): File => ({ name, bytes });
    const ballotFiles = [
        file('envelope.bin', ballot.envelopeBytes),
        file('signature.bin', registration.signatureBytes),
        file('body.bin', ballot.maximumBodyBytes),
    ];
    const ballotManifestBytes = compileCandidatePublication(
        'ballot-0',
        ballotFiles,
    ).manifestBytes;
    const bodyReference = (position: number): File => ({
        name: 'body-' + identity(position) + '.bin',
        bytes: ballot.maximumBodyBytes,
        referenceManifestBytes: ballotManifestBytes,
    });
    const responseBytes =
        close.minimumResponseBodyBytes +
        66n * BigInt(n) +
        4n +
        registration.signatureBytes;
    const publications: (ReturnType<typeof compileCandidatePublication> & {
        position: number;
    })[] = [];
    const publish = (position: number, name: string, files: readonly File[]) =>
        publications.push({
            position,
            ...compileCandidatePublication(
                name,
                files,
                name === 'setup-certificate' ? BigInt(n) : 1n,
            ),
        });
    const pollFiles = [
        file('definition.bin', registration.maximumPollDefinitionBytes),
        file('signature.bin', registration.signatureBytes),
    ];
    publish(0, 'poll', pollFiles);
    const registrationFiles = [
        file('polynomial-01.bin', key.publicKeyBytes),
        file('proof.bin', key.maximumProofBytes),
        file('registration-header.bin', registration.maximumHeaderBytes),
        file('signature.bin', registration.signatureBytes),
    ];
    for (let position = 0; position < n; position++)
        publish(
            position,
            'registration/' + identity(position),
            registrationFiles,
        );
    publish(0, 'poll', pollFiles);
    publish(0, 'registration/' + identity(0), registrationFiles);
    publish(0, 'roster', [
        file('proposal.bin', roster.proposalBytes),
        file('signature.bin', registration.signatureBytes),
    ]);
    for (let position = 0; position < offers; position++)
        publish(
            position,
            'contribution-' + String(position) + '/' + identity(position),
            [
                file('offer.bin', selection.offerEnvelopeBytes),
                file('offer-signature.bin', registration.signatureBytes),
                file('body-header.bin', offer.headerBytes),
                ...offer.polynomials.map((polynomial) =>
                    file(
                        'polynomial-' +
                            String(polynomial.expandedIndex).padStart(2, '0') +
                            '.bin',
                        polynomial.bytes,
                    ),
                ),
                file('proof.bin', offer.maximumProofBytes),
            ],
        );
    publish(0, 'selection', [
        file('selection.bin', selection.selectionBodyBytes),
        file('signature.bin', registration.signatureBytes),
    ]);
    for (let position = 0; position < n; position++) {
        publish(position, 'selection-endorsement-' + String(position), [
            file('endorsement.bin', selection.endorsementPacketBytes),
        ]);
        publish(position, 'setup-certificate', [
            file('certificate.bin', selection.certificateBytes),
        ]);
        publish(position, 'ballot-' + String(position), ballotFiles);
    }
    publish(0, 'close-intent', [file('intent.bin', close.intentPacketBytes)]);
    for (let position = 0; position < n; position++)
        publish(position, 'close-response-' + String(position), [
            file('response.bin', responseBytes),
            file('submissions.bin', BigInt(n) * close.submissionBytes),
            ...(position === 0
                ? []
                : Array.from({ length: n }, (_, author) =>
                      bodyReference(author),
                  )),
        ]);
    publish(0, 'close-intent', [file('intent.bin', close.intentPacketBytes)]);
    publish(0, 'close-proposal', [
        file('intent.bin', close.intentPacketBytes),
        file('proposal.bin', close.proposalPacketBytes),
        ...Array.from({ length: selection.quorum }, (_, position) =>
            file('response-' + identity(position) + '.bin', responseBytes),
        ),
        ...Array.from({ length: n }, (_, position) =>
            file(
                'submission-' + identity(position) + '.bin',
                close.submissionBytes,
            ),
        ),
        ...Array.from({ length: n }, (_, index) => bodyReference(index)),
    ]);
    for (let position = 0; position < n; position++) {
        publish(position, 'target-vote-' + String(position), [
            file('vote.bin', target.packetBytes),
            ...(position === 0
                ? [file('target.bin', target.maximumBodyBytes)]
                : []),
        ]);
        publish(position, 'release-' + String(position), [
            file('body.bin', release.maximumBodyBytes),
            file(
                'envelope.bin',
                release.envelopeBytes + registration.signatureBytes,
            ),
        ]);
    }
    const sum = (
        select: (publication: (typeof publications)[number]) => bigint,
    ) =>
        publications.reduce(
            (total, publication) => total + select(publication),
            0n,
        );
    const preparation = publications.filter(
        (publication) =>
            publication.key.startsWith('contribution-') ||
            publication.key === 'selection' ||
            publication.key.startsWith('selection-endorsement-') ||
            publication.key === 'setup-certificate',
    );
    const preparationParticipants = Array.from(
        { length: n },
        (_, position) => ({
            uploadedPayloadBytes:
                preparation.reduce(
                    (total, publication) =>
                        total +
                        (publication.position === position
                            ? publication.uploadedPayloadBytes
                            : 0n),
                    0n,
                ) + (position < offers ? 64n : 0n),
            receivedPayloadBytes: preparation.reduce(
                (total, publication) =>
                    total +
                    (publication.position === position
                        ? publication.receivedPayloadBytes
                        : 0n),
                0n,
            ),
        }),
    );
    return {
        publications,
        publicationCount: BigInt(publications.length),
        uploadedPayloadBytes:
            sum((publication) => publication.uploadedPayloadBytes) +
            BigInt(offers) * 64n,
        receivedPayloadBytes: sum(
            (publication) => publication.receivedPayloadBytes,
        ),
        readbackPayloadBytes: sum(
            (publication) => publication.readbackPayloadBytes,
        ),
        storedPayloadBytes:
            sum((publication) => publication.storedPayloadBytes) +
            BigInt(offers) * 64n,
        receiptBytes: sum((publication) => publication.receiptBytes),
        manifestBytes: sum((publication) => publication.manifestBytes),
        requests: sum((publication) => publication.requests) + BigInt(offers),
        referencedBodyBytes: sum(
            (publication) =>
                publication.payloadBytes -
                publication.uploadedPayloadBytes +
                publication.manifestBytes,
        ),
        maximumManifestBytes: maximum(
            publications.map((publication) => publication.manifestBytes),
        ),
        maximumFiles: maximum(
            publications.map((publication) => publication.files),
        ),
        preparation: {
            publications: preparation,
            participants: preparationParticipants,
            uploadedPayloadBytes: preparationParticipants.reduce(
                (total, participant) =>
                    total + participant.uploadedPayloadBytes,
                0n,
            ),
            maximumParticipantUploadBytes: maximum(
                preparationParticipants.map(
                    (participant) => participant.uploadedPayloadBytes,
                ),
            ),
            maximumParticipantReceivedBytes: maximum(
                preparationParticipants.map(
                    (participant) => participant.receivedPayloadBytes,
                ),
            ),
        },
        participants: Array.from({ length: n }, (_, position) => ({
            uploadedPayloadBytes:
                sum((publication) =>
                    publication.position === position
                        ? publication.uploadedPayloadBytes
                        : 0n,
                ) + (position < offers ? 64n : 0n),
            receivedPayloadBytes: sum((publication) =>
                publication.position === position
                    ? publication.receivedPayloadBytes
                    : 0n,
            ),
        })),
    };
};
