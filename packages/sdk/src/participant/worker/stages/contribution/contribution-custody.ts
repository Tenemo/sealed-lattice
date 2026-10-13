import type { ParticipantProfileContext } from '../../module/context.js';
import {
    custodyIdentity,
    custodyPurpose,
} from '../../module/custody-identity.js';
import { moduleCommand } from '../../module/participant-module.js';
import {
    isContributionSession,
    resumeParticipant,
} from '../../runtime/participant-session.js';
import type {
    ParticipantSession,
    ContributionSession,
} from '../../runtime/participant-session.js';
import { equalBytes } from '../../shared/bytes.js';
import { readParticipantValue, recordBytes } from '../../storage/database.js';
import {
    openSealedRecord,
    sealRecord,
    sealedLength,
} from '../../storage/private-records.js';
import { rootGeneration } from '../../storage/root-generation.js';
import type { AuthenticatedRoot } from '../../storage/root.js';
import { commitRoot, dataRecordInventory } from '../../storage/root.js';
import type { VerifiedProposal } from '../roster/roster.js';

import {
    recordAssociatedData,
    signingObject,
    contributionInventory,
    encodeContributionState,
} from './contribution-state.js';
import type {
    ContributionRecord,
    SigningKind,
    ContributionState,
} from './contribution-state.js';
import { encodePreparationState } from './preparation-state.js';

export const offerSigningOperation = {
    beginBody: 1,
    polynomial: 2,
    proof: 3,
    finishBody: 4,
    signOffer: 5,
    bodyHeader: 8,
} as const;

export type SealedOutput = Readonly<{
    record: ContributionRecord;
    ciphertext: Uint8Array;
}>;

export const sealContributionRecord = async (
    session: ParticipantSession,
    object: number,
    offset: number,
    bytes: Uint8Array,
): Promise<SealedOutput> => {
    const location = { object, offset, length: bytes.length };
    const { key, ciphertext } = await sealRecord(
        recordAssociatedData(session.records, location),
        bytes,
    );
    return {
        record: {
            ...location,
            key,
            hash: custodyIdentity(
                session.context.module,
                custodyPurpose.record,
                ciphertext,
            ),
        },
        ciphertext,
    };
};

export const openContributionRecord = async (
    session: ParticipantSession,
    record: ContributionRecord,
) => {
    const blob = await readParticipantValue(
        session.context.database,
        'contribution',
        [record.object, record.offset],
    );
    if (!(blob instanceof Blob) || blob.size !== sealedLength(record.length))
        throw new Error('A contribution record is missing.');
    const ciphertext = await recordBytes(blob);
    if (
        !equalBytes(
            custodyIdentity(
                session.context.module,
                custodyPurpose.record,
                ciphertext,
            ),
            record.hash,
        )
    )
        throw new Error('A contribution record changed.');
    return openSealedRecord(
        record.key,
        recordAssociatedData(session.records, record),
        ciphertext,
    );
};

export const openSigning = (
    session: ContributionSession,
    kind: SigningKind,
) => {
    const object = signingObject(session.context.profile, kind);
    const record = session.state.signingRecords.find(
        (value) => value.object === object,
    );
    if (record === undefined)
        throw new Error('A contribution signing record is missing.');
    return openContributionRecord(session, record);
};

type ContributionTransition = Readonly<{
    state: ContributionState;
    // Generated records stored ahead of this root; its transition checks
    // that each one opens before it commits.
    staged?: boolean;
    // Signing records written with the root.
    signing?: readonly SealedOutput[];
    clearCheckpoint?: boolean;
}>;

export const commitContribution = async (
    session: ParticipantSession,
    transition: ContributionTransition,
) => {
    const { context, root } = session;
    const profile = context.profile;
    const predecessor =
        root.head.generation >= rootGeneration.preparation &&
        session.state !== undefined
            ? contributionInventory(profile, session.state, session.records)
            : [];
    const listed = new Set(
        predecessor.map(
            (record) => record.store + ':' + JSON.stringify(record.key),
        ),
    );
    const staged =
        transition.staged === true
            ? contributionInventory(
                  profile,
                  transition.state,
                  session.records,
              ).filter(
                  (record) =>
                      !listed.has(
                          record.store + ':' + JSON.stringify(record.key),
                      ),
              )
            : [];
    const preparation = {
        ...session.preparation,
        contribution: encodeContributionState(transition.state),
    };
    session.root = await commitRoot(context, root, {
        generation: rootGeneration.preparation,
        manifest: {
            ...root.manifest,
            suffixes: {
                ...root.manifest.suffixes,
                preparation: encodePreparationState(preparation),
            },
        },
        predecessorRecords: [
            ...dataRecordInventory(root.manifest),
            ...predecessor,
        ],
        stagedRecords: staged,
        write: (transaction) => {
            for (const output of transition.signing ?? [])
                transaction
                    .objectStore('contribution')
                    .add(new Blob([new Uint8Array(output.ciphertext)]), [
                        output.record.object,
                        output.record.offset,
                    ]);
            if (transition.clearCheckpoint === true)
                transaction.objectStore('checkpoint').clear();
        },
    });
    session.state = transition.state;
    session.preparation = preparation;
    for (const output of transition.signing ?? [])
        (await openContributionRecord(session, output.record)).fill(0);
};

export const signing = (
    context: ParticipantProfileContext,
    operation: number,
    bytes: Uint8Array = new Uint8Array(),
    argument = 0,
) =>
    moduleCommand(context.module, 'offerSigning', operation, {
        argument,
        input: bytes,
    });

export const resumeContribution = async (
    context: ParticipantProfileContext,
    root: AuthenticatedRoot,
    verified?: VerifiedProposal,
): Promise<ContributionSession> => {
    const session = await resumeParticipant(context, root, verified);
    if (!isContributionSession(session))
        throw new Error('No own contribution is retained.');
    return session;
};
