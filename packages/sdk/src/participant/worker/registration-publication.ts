import { hexadecimal } from './bytes.js';
import type { ParticipantContext } from './context.js';
import { openDelivery } from './delivery.js';
import type { RestoredEnrollment } from './enrollment.js';
import { createCandidatePublication } from './public.js';
import type { PublicRelay } from './public.js';
import { dataKind, readDataRecord } from './root.js';
import type { AuthenticatedRoot } from './root.js';
import { registrationFile, registrationCandidateKey } from './roster.js';

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
    const groups: [string, [number, string][]][] = [
        [
            registrationCandidateKey(id),
            [
                [dataKind.publicKey, registrationFile.publicKey],
                [dataKind.header, registrationFile.header],
                [dataKind.signature, registrationFile.signature],
            ],
        ],
    ];
    if (enrollment.isOrganizer) {
        groups.push([
            'poll',
            [
                [dataKind.pollDefinition, 'definition.bin'],
                [dataKind.pollSignature, 'signature.bin'],
            ],
        ]);
        if (root.head.generation >= 3)
            groups.push([
                'roster',
                [
                    [dataKind.proposal, 'proposal.bin'],
                    [dataKind.proposalSignature, 'signature.bin'],
                ],
            ]);
    }
    const delivery = await openDelivery(context, root);
    for (const [key, files] of groups) {
        const publication = createCandidatePublication(relay, key, delivery);
        for (const [kind, name] of files) {
            const references = root.manifest.references.filter(
                (reference) => reference.kind === kind,
            );
            await delivery.transfer(async () => {
                for (const reference of references)
                    (await readDataRecord(context, reference)).fill(0);
            });
            await publication.addStream(
                name,
                references.reduce(
                    (total, reference) => total + reference.length,
                    0,
                ),
                async (accept) => {
                    for (const reference of references) {
                        const bytes = await readDataRecord(context, reference);
                        try {
                            await accept(bytes);
                        } finally {
                            bytes.fill(0);
                        }
                    }
                },
            );
        }
        await publication.finish();
    }
};
