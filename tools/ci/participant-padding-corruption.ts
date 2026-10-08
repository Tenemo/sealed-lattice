import {
    custodyIdentities,
    custodyIdentity,
    custodyPurpose,
} from '#packages/sdk/src/participant/worker/module/custody-identity.js';
import { noParallelHelpers } from '#packages/sdk/src/participant/worker/module/parallel-helpers.js';
import { instantiateParticipantModule } from '#packages/sdk/src/participant/worker/module/participant-module.js';
import { readParticipantLimits } from '#packages/sdk/src/participant/worker/module/runtime-bounds.js';
import {
    equalBytes,
    fromHexadecimal,
    hexadecimal,
} from '#packages/sdk/src/participant/worker/shared/bytes.js';
import { proofLength } from '#packages/sdk/src/participant/worker/stages/contribution/contribution-proof.js';
import {
    contributionRecords,
    encodeContributionState,
    resumeContribution,
} from '#packages/sdk/src/participant/worker/stages/contribution/contribution.js';
import { encodePreparationState } from '#packages/sdk/src/participant/worker/stages/contribution/preparation-state.js';
import { restoreEnrollment } from '#packages/sdk/src/participant/worker/stages/enrollment/enrollment.js';
import { retainedProfile } from '#packages/sdk/src/participant/worker/stages/roster/roster.js';
import {
    openParticipantDatabase,
    participantRecordStores,
    participantStores,
    readParticipantValue,
} from '#packages/sdk/src/participant/worker/storage/database.js';
import { validateParticipantPredecessor } from '#packages/sdk/src/participant/worker/storage/predecessor.js';
import {
    openRecord,
    sealRecord,
} from '#packages/sdk/src/participant/worker/storage/private-records.js';
import {
    authenticateRoot,
    commitRoot,
    dataRecordInventory,
    rootAssociatedData,
} from '#packages/sdk/src/participant/worker/storage/root.js';
import { commitParticipantState } from '#packages/sdk/src/participant/worker/storage/state-transaction.js';

type ParticipantPaddingMutation = Readonly<{
    namespace: string;
    runtimeIdentity: string;
    moduleDigest: string;
    participants: number;
    options: number;
    position: number;
    kind: 'missing' | 'nonzero';
}>;

// Browser-only development control, bundled by the guarded runner and run
// inside an isolated copy of a contributor's Chrome profile. No keys or
// plaintext leave that browser. The caller closes the copy after the probe.
export const mutateParticipantPadding = async (
    options: ParticipantPaddingMutation,
) => {
    if (
        !/^[0-9a-f]{128}$/u.test(options.runtimeIdentity) ||
        !/^[0-9a-f]{128}$/u.test(options.moduleDigest) ||
        !['missing', 'nonzero'].includes(options.kind)
    )
        throw new Error('Invalid padding mutation parameters.');
    const response = await fetch('/sdk/participant.wasm');
    if (!response.ok) throw new Error('The participant module is unavailable.');
    const moduleBytes = new Uint8Array(await response.arrayBuffer());
    if (
        hexadecimal(
            new Uint8Array(await crypto.subtle.digest('SHA-512', moduleBytes)),
        ) !== options.moduleDigest
    )
        throw new Error('The padding control received another module.');
    const { module, handlers } = await instantiateParticipantModule(
        await WebAssembly.compile(moduleBytes),
        noParallelHelpers,
    );
    if (module.worker_reserve(0, 0) !== 0)
        throw new Error('The padding control memory plan was refused.');
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
                'The padding control requires ongoing preparation.',
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
            throw new Error('The padding control names another participant.');
        const session = await resumeContribution(context, root);
        const state = session.state;
        if (state.phase !== 7)
            throw new Error(
                'The padding control requires the complete unsigned offer body.',
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
            record.offset + record.length <= logicalLength
        )
            throw new Error('The retained proof has no padding to mutate.');
        const used = Math.max(0, logicalLength - record.offset);
        const inventory = contributionRecords(session);
        const required = inventory.find(
            (value) =>
                Array.isArray(value.key) &&
                value.key[0] === record.object &&
                value.key[1] === record.offset,
        );
        if (required?.encryption === undefined)
            throw new Error(
                'The padding slot has no authenticated record context.',
            );
        const coordinates = [record.object, record.offset];
        const plaintext = await openRecord(
            database,
            'contribution',
            coordinates,
            required.encryption,
            record.length,
        );
        privateBytes.push(plaintext);
        if (plaintext.subarray(used).some((byte) => byte !== 0))
            throw new Error('The original padding is not zero.');
        const predecessorRecords = [
            ...dataRecordInventory(root.manifest),
            ...inventory,
        ];
        if (options.kind === 'missing') {
            await commitParticipantState({
                database,
                stores: participantStores,
                timeoutMilliseconds: 60_000,
                validate: (reader) =>
                    validateParticipantPredecessor(reader, {
                        head: root.head,
                        manifest: root.plaintext,
                        rootContext: rootAssociatedData(context.runtime),
                        maximumRootBytes: context.profile.root.maximumRootBytes,
                        recordStores: participantRecordStores,
                        records: predecessorRecords,
                        identities: custodyIdentities(module),
                    }),
                write: (transaction) => {
                    transaction.objectStore('contribution').delete(coordinates);
                },
            });
            if (
                (await readParticipantValue(
                    database,
                    'contribution',
                    coordinates,
                )) !== undefined
            )
                throw new Error('The padding slot deletion did not persist.');
        } else {
            // This public final-slot coordinate is padding even when the
            // same slot begins with the proof's final canonical bytes.
            plaintext[plaintext.length - 1] = 1;
            // Both record and root encrypt under fresh keys. The existing
            // root writer authenticates the original inventory atomically.
            const sealed = await sealRecord(
                required.encryption.additionalData,
                plaintext,
            );
            privateBytes.push(sealed.key);
            const replacement = {
                ...record,
                key: sealed.key,
                hash: custodyIdentity(
                    module,
                    custodyPurpose.record,
                    sealed.ciphertext,
                ),
            };
            const suffix = encodeContributionState({
                ...state,
                publicRecords: state.publicRecords.map((value) =>
                    value === record ? replacement : value,
                ),
            });
            privateBytes.push(suffix);
            const committed = await commitRoot(context, root, {
                generation: 4,
                manifest: {
                    ...root.manifest,
                    suffixes: {
                        preparation: encodePreparationState({
                            ...session.preparation,
                            contribution: suffix,
                        }),
                    },
                },
                predecessorRecords,
                write: (transaction) => {
                    transaction
                        .objectStore('contribution')
                        .put(
                            new Blob([new Uint8Array(sealed.ciphertext)]),
                            coordinates,
                        );
                },
            });
            privateBytes.push(committed.plaintext);
            const reopened = await openRecord(
                database,
                'contribution',
                coordinates,
                {
                    key: sealed.key,
                    additionalData: required.encryption.additionalData,
                },
                record.length,
            );
            privateBytes.push(reopened);
            if (!equalBytes(reopened, plaintext))
                throw new Error(
                    'The authenticated padding mutation did not persist.',
                );
        }
        const authenticated = await authenticateRoot(context);
        privateBytes.push(
            authenticated.plaintext,
            authenticated.manifest.dataKeys,
        );
        if (authenticated.head.generation !== 4)
            throw new Error(
                'The padding mutation moved the retained generation.',
            );
        return {
            kind: options.kind,
            object: record.object,
            offset: record.offset,
            length: record.length,
            paddingOnly: used === 0,
            rootAuthenticated: true,
            originalPaddingAuthenticated: true,
            mutationReadback: true,
        };
    } finally {
        for (const bytes of privateBytes) bytes.fill(0);
        database.close();
    }
};
