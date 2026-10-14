import { writeModuleInput } from '../module/context.js';
import type { ParticipantProfileContext } from '../module/context.js';
import { readModuleMemory } from '../module/participant-module.js';
import { identityBytes } from '../module/runtime-bounds.js';
import { concatenate, unsigned16, unsigned32 } from '../shared/bytes.js';
import { snapshotParticipant } from '../storage/database.js';
import { rootGeneration } from '../storage/root-generation.js';
import type { AuthenticatedRoot } from '../storage/root.js';
import {
    authenticateRecords,
    commitRoot,
    dataKind,
    dataRecordInventory,
    readDataKind,
} from '../storage/root.js';

import {
    decodeContributionState,
    discardInterruptedRecords,
    contributionInventory,
} from './contribution/contribution-state.js';
import type {
    ProposalRecordContext,
    ContributionState,
} from './contribution/contribution-state.js';
import {
    decodePreparationState,
    encodePreparationState,
} from './contribution/preparation-state.js';
import type { PreparationState } from './contribution/preparation-state.js';

// Every original roster member has the same preparation journal. Own offer
// work is optional and advances independently from quorum selection.
export type ParticipantSession = {
    readonly context: ParticipantProfileContext;
    readonly records: ProposalRecordContext;
    root: AuthenticatedRoot;
    state?: ContributionState;
    preparation: PreparationState;
};

export type ContributionSession = ParticipantSession & {
    state: ContributionState;
};

export const isContributionSession = (
    session: ParticipantSession,
): session is ContributionSession => session.state !== undefined;

// Has the module retain the stored proposal's context at this participant's
// position and returns the proposal's identity.
const retainProposal = async (
    context: ParticipantProfileContext,
    root: AuthenticatedRoot,
) => {
    const { module } = context;
    const proposal = await readDataKind(
        context,
        root.manifest,
        dataKind.proposal,
    );
    const control = concatenate(
        root.manifest.poll,
        unsigned16(context.position),
        unsigned32(proposal.length),
        proposal,
    );
    writeModuleInput(context, control);
    if (module.retain_proposal(control.length) !== 0)
        throw new Error('The retained proposal context was refused.');
    return readModuleMemory(
        module,
        module.retained_proposal_identity_pointer(),
        identityBytes,
    );
};

export const resumeParticipant = async (
    context: ParticipantProfileContext,
    root: AuthenticatedRoot,
): Promise<ParticipantSession> => {
    const { generation } = root.head;
    const suffix = root.manifest.suffixes.preparation;
    if (
        generation < rootGeneration.rosterSigned ||
        (generation === rootGeneration.rosterSigned) !== (suffix === undefined)
    )
        throw new Error('No accepted roster is retained.');
    const preparation =
        suffix === undefined
            ? {}
            : decodePreparationState(suffix, context.profile);
    if (
        generation >= rootGeneration.setupRetained &&
        Object.keys(preparation).length !== 0
    )
        throw new Error('Retired preparation authority is still present.');
    const state =
        preparation.contribution === undefined
            ? undefined
            : decodeContributionState(
                  preparation.contribution,
                  context.profile,
              );
    if (state !== undefined && state.position !== context.position)
        throw new Error('The retained offer names another participant.');
    await discardInterruptedRecords(context, state);
    const snapshot = await snapshotParticipant(context.database);
    if (
        snapshot.counts.contribution !==
            (state === undefined
                ? 0
                : state.publicRecords.length + state.signingRecords.length) ||
        snapshot.counts.checkpoint !== (state?.privateRecords.length ?? 0)
    )
        throw new Error('The contribution records changed.');
    const proposal = await retainProposal(context, root);
    if (
        generation >= rootGeneration.preparation &&
        context.module.confirm_roster() !== 0
    )
        throw new Error('The original confirmed roster could not be restored.');
    const session: ParticipantSession = {
        context,
        root,
        preparation,
        records: {
            poll: root.manifest.poll,
            proposal,
            position: context.position,
        },
        ...(state === undefined ? {} : { state }),
    };
    if (generation < rootGeneration.setupRetained)
        await authenticateRecords(context, root, [
            ...dataRecordInventory(root.manifest),
            ...contributionRecords(session),
        ]);
    return session;
};

export const commitPreparation = async (
    session: ParticipantSession,
    update: Pick<PreparationState, 'selection' | 'endorsement'>,
) => {
    if (
        session.root.head.generation !== rootGeneration.rosterSigned &&
        session.root.head.generation !== rootGeneration.preparation
    )
        throw new Error('Preparation is already retired.');
    const preparation = { ...session.preparation, ...update };
    session.root = await commitRoot(session.context, session.root, {
        generation: rootGeneration.preparation,
        manifest: {
            ...session.root.manifest,
            suffixes: { preparation: encodePreparationState(preparation) },
        },
        predecessorRecords: [
            ...dataRecordInventory(session.root.manifest),
            ...contributionRecords(session),
        ],
    });
    session.preparation = preparation;
};

// The human confirms the displayed, verified roster before any setup work.
export const confirmRoster = async (session: ParticipantSession) => {
    if (session.root.head.generation === rootGeneration.rosterSigned)
        await commitPreparation(session, {});
    if (session.context.module.confirm_roster() !== 0)
        throw new Error('The credential refused the confirmed roster.');
};

// The stored records the retained contribution or roster confirmation
// lists, if any.
export const contributionRecords = (session: ParticipantSession) =>
    isContributionSession(session)
        ? contributionInventory(
              session.context.profile,
              session.state,
              session.records,
          )
        : [];
