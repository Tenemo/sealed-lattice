import { hexadecimal } from './bytes.js';
import type { ParticipantContext } from './context.js';
import { openDelivery } from './delivery.js';
import type { RestoredEnrollment } from './enrollment.js';
import { publishChunk } from './public.js';
import type { PublicRelay } from './public.js';
import { dataKind, readDataRecord } from './root.js';
import type { AuthenticatedRoot } from './root.js';
import { registrationFile, registrationPath } from './roster.js';

// Publishes the registration and the organizer's retained poll and roster.
// The authenticated manifest has contiguous records of at most one transfer
// chunk, with only the last record of a kind shorter. Every kind authenticates
// completely before its first POST, without keeping a whole-file copy. The
// delivery pass checks each record again and inspects retained authority after
// every transfer, including a failed read or transfer.
export const publishRegistrationRecords = async (
    context: ParticipantContext,
    relay: PublicRelay,
    root: AuthenticatedRoot,
    enrollment: RestoredEnrollment,
) => {
    const id = hexadecimal(enrollment.bodyDigest);
    const files: [number, string][] = [
        [dataKind.publicKey, registrationPath(id, registrationFile.publicKey)],
        [dataKind.proof, registrationPath(id, registrationFile.proof)],
        [dataKind.header, registrationPath(id, registrationFile.header)],
        [dataKind.signature, registrationPath(id, registrationFile.signature)],
    ];
    if (enrollment.isOrganizer) {
        files.push(
            [dataKind.pollDefinition, 'poll-definition.bin'],
            [dataKind.pollSignature, 'poll-signature.bin'],
        );
        if (root.head.generation >= 3)
            files.push(
                [dataKind.proposal, 'proposal.bin'],
                [dataKind.proposalSignature, 'proposal-signature.bin'],
            );
    }
    const delivery = await openDelivery(context, root);
    for (const [kind, name] of files) {
        const references = root.manifest.references.filter(
            (reference) => reference.kind === kind,
        );
        await delivery.transfer(async () => {
            for (const reference of references)
                (await readDataRecord(context, reference)).fill(0);
        });
        for (const reference of references)
            await delivery.transfer(async () => {
                const bytes = await readDataRecord(context, reference);
                try {
                    await publishChunk(relay, name, reference.offset, bytes);
                } finally {
                    bytes.fill(0);
                }
            });
    }
};
