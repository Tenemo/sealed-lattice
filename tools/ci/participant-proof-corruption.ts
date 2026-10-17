import { custodyIdentities } from '#packages/sdk/src/participant/worker/module/custody-identity.js';
import { noParallelHelpers } from '#packages/sdk/src/participant/worker/module/parallel-helpers.js';
import { instantiateParticipantModule } from '#packages/sdk/src/participant/worker/module/participant-module.js';
import { readParticipantLimits } from '#packages/sdk/src/participant/worker/module/runtime-bounds.js';
import {
    fromHexadecimal,
    hexadecimal,
} from '#packages/sdk/src/participant/worker/shared/bytes.js';
import { proofLength } from '#packages/sdk/src/participant/worker/stages/contribution/contribution-proof.js';
import { restoreEnrollment } from '#packages/sdk/src/participant/worker/stages/enrollment/enrollment.js';
import {
    contributionRecords,
    isContributionSession,
    resumeParticipant,
} from '#packages/sdk/src/participant/worker/stages/participant-session.js';
import { retainedProfile } from '#packages/sdk/src/participant/worker/stages/roster/roster.js';
import {
    openParticipantDatabase,
    participantRecordStores,
    participantStores,
    readParticipantValue,
} from '#packages/sdk/src/participant/worker/storage/database.js';
import { validateParticipantPredecessor } from '#packages/sdk/src/participant/worker/storage/predecessor.js';
import {
    authenticateRoot,
    dataRecordInventory,
} from '#packages/sdk/src/participant/worker/storage/root.js';
import { commitParticipantState } from '#packages/sdk/src/participant/worker/storage/state-transaction.js';

type ParticipantProofMutation = Readonly<{
    namespace: string;
    runtimeIdentity: string;
    moduleDigest: string;
    participants: number;
    options: number;
    position: number;
    kind: 'missing' | 'altered';
}>;

// Browser-only development control, bundled by the guarded runner and run
// inside an isolated copy of a contributor's Chrome profile. No keys or
// plaintext leave that browser. The caller closes the copy after the probe.
export const mutateParticipantProof = async (
    options: ParticipantProofMutation,
) => {
    if (
        !/^[0-9a-f]{128}$/u.test(options.runtimeIdentity) ||
        !/^[0-9a-f]{128}$/u.test(options.moduleDigest) ||
        !['missing', 'altered'].includes(options.kind)
    )
        throw new Error('Invalid proof record mutation parameters.');
    const response = await fetch('/sdk/participant.wasm');
    if (!response.ok) throw new Error('The participant module is unavailable.');
    const moduleBytes = new Uint8Array(await response.arrayBuffer());
    if (
        hexadecimal(
            new Uint8Array(await crypto.subtle.digest('SHA-512', moduleBytes)),
        ) !== options.moduleDigest
    )
        throw new Error('The proof record control received another module.');
    const { module, handlers } = await instantiateParticipantModule(
        await WebAssembly.compile(moduleBytes),
        noParallelHelpers,
    );
    if (module.worker_reserve(0, 0) !== 0)
        throw new Error('The proof record control memory plan was refused.');
    const database = await openParticipantDatabase(options.namespace);
    const privateBytes: Uint8Array[] = [];
    try {
        const initial = {
            namespace: options.namespace,
            database,
            module,
            handlers,
            parallel: noParallelHelpers,
            runtime: fromHexadecimal(options.runtimeIdentity),
            limits: readParticipantLimits(module),
            separateEvaluation: false,
        };
        const root = await authenticateRoot(initial);
        privateBytes.push(root.plaintext, root.manifest.dataKeys);
        if (root.head.generation !== 4)
            throw new Error(
                'The proof record control requires ongoing preparation.',
            );
        const context = await retainedProfile(
            initial,
            root,
            await restoreEnrollment(initial, root, false),
        );
        if (
            context.profile.participantCount !== options.participants ||
            context.profile.optionCount !== options.options ||
            context.position !== options.position ||
            context.position >= context.profile.eligibleContributorCount
        )
            throw new Error(
                'The proof record control names another participant.',
            );
        const session = await resumeParticipant(context, root);
        if (!isContributionSession(session))
            throw new Error('No own contribution is retained.');
        const state = session.state;
        if (state.phase !== 7)
            throw new Error(
                'The proof record control requires the complete unsigned offer body.',
            );
        privateBytes.push(
            state.header,
            ...state.publicRecords.map((record) => record.key),
            ...state.signingRecords.map((record) => record.key),
        );
        const proofObject =
            context.profile.contribution.expandedPolynomials + 1;
        const record = state.publicRecords[state.publicRecords.length - 1];
        const logicalLength = proofLength(
            context.profile.contribution,
            state.header,
        );
        if (
            record === undefined ||
            record.object !== proofObject ||
            record.offset + record.length !== logicalLength
        )
            throw new Error('The retained proof has no exact final record.');
        const inventory = contributionRecords(session);
        const required = inventory.find(
            (value) =>
                Array.isArray(value.key) &&
                value.key[0] === record.object &&
                value.key[1] === record.offset,
        );
        if (required?.encryption === undefined)
            throw new Error(
                'The proof record slot has no authenticated record context.',
            );
        const coordinates = [record.object, record.offset];
        const predecessorRecords = [
            ...dataRecordInventory(root.manifest),
            ...inventory,
        ];
        await commitParticipantState({
            database,
            stores: participantStores,
            timeoutMilliseconds: 60_000,
            validate: (reader) =>
                validateParticipantPredecessor(reader, {
                    head: root.head,
                    manifest: root.plaintext,
                    rootContext: context.runtime,
                    maximumRootBytes: context.profile.root.maximumRootBytes,
                    recordStores: participantRecordStores,
                    records: predecessorRecords,
                    identities: custodyIdentities(module),
                }),
            write: (transaction) => {
                const store = transaction.objectStore('contribution');
                if (options.kind === 'missing') store.delete(coordinates);
                else {
                    const request = store.get(coordinates);
                    request.onsuccess = () => {
                        const blob = request.result as Blob;
                        store.put(new Blob([blob.slice(0, -1)]), coordinates);
                    };
                }
            },
        });
        const changed = await readParticipantValue(
            database,
            'contribution',
            coordinates,
        );
        if (
            options.kind === 'missing'
                ? changed !== undefined
                : !(changed instanceof Blob) ||
                  changed.size !== record.length + 15
        )
            throw new Error(
                'The required proof record mutation did not persist.',
            );
        const authenticated = await authenticateRoot(context);
        privateBytes.push(
            authenticated.plaintext,
            authenticated.manifest.dataKeys,
        );
        if (authenticated.head.generation !== 4)
            throw new Error(
                'The proof record mutation moved the retained generation.',
            );
        return {
            kind: options.kind,
            object: record.object,
            offset: record.offset,
            length: record.length,
            rootAuthenticated: true,
            mutationReadback: true,
        };
    } finally {
        for (const bytes of privateBytes) bytes.fill(0);
        database.close();
    }
};
