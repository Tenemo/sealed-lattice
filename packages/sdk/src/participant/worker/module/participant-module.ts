import { ModuleFailure, ResourceFailure } from '../shared/failures.js';

import type { ParallelHelpers } from './parallel-helpers.js';

// The participant scalar module's exports that the worker calls. Every
// command returns zero when it accepts and one when it refuses, and a query's
// comment states its answer; the owning Rust state machine decides
// acceptance.
export const moduleFunctions = [
    // The shared bounds and one profile's, each written as 64-bit words; a
    // command returns the word count, zero for an unsupported profile.
    'participant_bounds_pointer',
    'participant_limits',
    'participant_profile_bounds',
    // The highest linear-memory address any allocation has reached.
    'linear_memory_high_water',
    // The bounds of the memory plan of an operation with a helper count,
    // which evaluates the ranking program when the flag is one; zero
    // without a plan. Reserve lowers the instance's bound to the worker's
    // share before its first allocation.
    'helper_memory_bound',
    'worker_memory_bound',
    'worker_reserve',
    'input_pointer',
    'input_capacity',
    'poll_identity_pointer',
    'validate_organizer',
    'validate_joiner',
    'prepare_organizer',
    'prepare_joiner',
    'restore',
    'restore_prepared',
    'retire_contribution_sources',
    'check_retained',
    'own_registration_input_pointer',
    'own_registration_input_capacity',
    'own_registration_command',
    'own_registration_body_digest_pointer',
    'own_registration_username_pointer',
    'own_registration_username_length',
    // The verified poll's option count, or zero before verification.
    'own_registration_option_count',
    // The verified poll's participant maximum, or zero before verification.
    'own_registration_maximum_participants',
    // Writes the verified poll's result length, question and options to the
    // contribution output.
    'own_registration_poll',
    'roster_begin',
    // Restores the retained roster from the begin input and the retained
    // roster after it.
    'roster_begin_retained',
    // The registration records the worker may stream at once.
    'roster_open_records',
    'roster_record',
    'roster_finish',
    'roster_body_pointer',
    'roster_body_length',
    'roster_identity_pointer',
    // Writes the verified proposal's usernames in roster order to the
    // contribution output, each as its four-byte length and its bytes.
    'roster_usernames',
    'validate_roster_signer',
    'sign_roster_proposal',
    'roster_signature_pointer',
    'verify_roster_signature',
    // Emits the credential-keyed retained roster of a roster verified in
    // full.
    'retain_roster',
    // The module's verification of the participant's own registration,
    // keyed to the restored credential.
    'retain_registration',
    'retain_proposal',
    'retained_proposal_identity_pointer',
    'participant_ballot_command',
    'participant_ballot_key_index',
    'participant_close_command',
    'participant_finality_command',
    'participant_release_command',
    // The inventory certificate, release contexts and release shares.
    'completion_input_pointer',
    'completion_input_capacity',
    'completion_output_pointer',
    'completion_output_length',
    'completion_command',
    // The public close barrier verifier.
    'close_input_pointer',
    'close_input_capacity',
    'close_command',
    'close_missing_pointer',
    'close_missing_count',
    // The signed ballot classifier. Finish returns one for a valid body, two
    // for an invalid one and zero when classification refused.
    'ballot_body_input_pointer',
    'ballot_body_input_capacity',
    'ballot_classification_begin',
    // One when the body relation needs its encryption keys.
    'ballot_classification_requires_key',
    // The aggregate polynomial of the key at an ordinal under the verified
    // setup, or the maximum value without one.
    'ballot_classification_key_index',
    'ballot_classification_key_begin',
    'ballot_classification_key_chunk',
    'ballot_classification_key_finish',
    'ballot_classification_chunk',
    'ballot_classification_finish',
    // The public ranking evaluation.
    'evaluation_target_input_pointer',
    'evaluation_target_input_capacity',
    'evaluation_target_output_pointer',
    'evaluation_target_output_length',
    'evaluation_target_command',
    'evaluation_target_body_pointer',
    'evaluation_target_body_length',
    // One when every evaluation step has run.
    'evaluation_target_finished',
    // The evaluated target keyed to the credential, and its restoration:
    // zero begins a copy of a length, one appends input bytes and two
    // restores it.
    'retain_evaluation',
    'restore_evaluation',
    'confirm_roster',
    'offer_signing_command',
    'selection_signing_command',
    'retain_selection_inputs',
    'restore_selection_inputs',
    'contribution_output_pointer',
    'contribution_output_length',
    'begin_contribution',
    'contribution_proof_input_pointer',
    'contribution_proof_input_capacity',
    'contribution_proof_command',
    'contribution_proof_phase',
    'contribution_proof_output_pointer',
    'contribution_proof_output_length',
    'contribution_checkpoint_records',
    'contribution_checkpoint_command',
    'contribution_checkpoint_key',
    // The randomness of a contribution generation or continuation, a ballot
    // or a release, expanded from the seed its root retains.
    'operation_random_input_pointer',
    'operation_random_command',
    'operation_random_drawn',
    'setup_input_pointer',
    'setup_input_capacity',
    'setup_chunk_capacity',
    'setup_roster_begin',
    'setup_roster_begin_retained',
    'setup_roster_record',
    'setup_roster_finish',
    // The verified roster's poll option count, or zero before it verifies.
    'setup_option_count',
    'setup_output_pointer',
    'setup_output_length',
    'setup_offer_begin',
    'setup_offer_polynomial',
    'setup_offer_proof',
    'setup_offer_finish',
    // One when a verified offer has the position and body identity.
    'setup_offer_available',
    'setup_selection_build',
    'setup_selection_begin',
    'setup_selection_count',
    'setup_selection_position',
    'setup_selection_body_identity_pointer',
    'setup_selection_identity_pointer',
    'setup_selection_aggregate',
    'setup_begin_selected_offer',
    'setup_begin_selected_offer_verification',
    'setup_polynomial',
    'setup_selected_offer_proof',
    'setup_finish_selected_offer',
    'setup_accepted',
    'setup_selection_finish',
    'setup_discard_aggregation',
    'setup_endorsement',
    'setup_certificate_build',
    'setup_certificate',
    'setup_finish_certificate',
    'retain_setup',
    // Restores the verified setup from the retained setup reference.
    'restore_setup',
    // The identities the runtime binds into its retained state.
    'custody_identity_input_pointer',
    'custody_identity_input_capacity',
    'custody_identity_output_pointer',
    'custody_identity_begin',
    'custody_identity_absorb',
    'custody_identity_finish',
] as const;

type ModuleFunction = (...values: number[]) => number;
export type ParticipantModule = Readonly<
    Record<(typeof moduleFunctions)[number], ModuleFunction> & {
        memory: WebAssembly.Memory;
    }
>;

export type ModuleHandlers = {
    random?: (target: Uint8Array<ArrayBuffer>) => void;
    staged?: (kind: number, offset: number, bytes: Uint8Array) => void;
    contribution?: (object: number, offset: number, bytes: Uint8Array) => void;
};

// Randomness requests are bounded before any view of module memory exists.
const maximumRandomRequest = 65_536;

export type LoadedModule = Readonly<{
    module: ParticipantModule;
    // Handlers for the current operation; an absent handler refuses.
    handlers: ModuleHandlers;
}>;

export const instantiateParticipantModule = async (
    compiledModule: WebAssembly.Module,
    helpers: ParallelHelpers,
): Promise<LoadedModule> => {
    const handlers: ModuleHandlers = {};
    const instantiated: { memory?: WebAssembly.Memory } = {};
    const view = (pointer: number, length: number) => {
        if (instantiated.memory === undefined)
            throw new Error('The participant module is not ready.');
        return new Uint8Array(
            instantiated.memory.buffer,
            pointer >>> 0,
            length >>> 0,
        );
    };
    // Fresh randomness for the purpose each import names: registration and
    // credential generation, witnesses, and proofs. An installed operation
    // seed serves its operation's draws within the module.
    const random = (pointer: number, length: number) => {
        if (handlers.random === undefined || length > maximumRandomRequest)
            throw new Error('Unexpected participant randomness request.');
        handlers.random(view(pointer, length));
        return 0;
    };
    const instance = await WebAssembly.instantiate(compiledModule, {
        allocator: {
            exhausted: (bytes: number) => {
                throw new ResourceFailure(
                    'The participant module exhausted its memory bound, ' +
                        String(bytes >>> 0) +
                        ' bytes requested.',
                );
            },
        },
        parallel: helpers.imports(() => {
            if (instantiated.memory === undefined)
                throw new Error('The participant module is not ready.');
            return instantiated.memory;
        }),
        enrollment: {
            fill_random: random,
            staged_chunk: (
                kind: number,
                offset: number,
                pointer: number,
                length: number,
            ) => {
                if (handlers.staged === undefined)
                    throw new Error('Unexpected enrollment record.');
                handlers.staged(
                    kind,
                    offset >>> 0,
                    view(pointer, length).slice(),
                );
                return 0;
            },
        },
        setup_witness: { fill_random: random },
        word_proof: { fill_random: random },
        contribution: {
            public_chunk: (
                object: number,
                offset: number,
                pointer: number,
                length: number,
            ) => {
                if (handlers.contribution === undefined)
                    throw new Error('Unexpected contribution record.');
                handlers.contribution(
                    object,
                    offset >>> 0,
                    view(pointer, length).slice(),
                );
                return 0;
            },
        },
    });
    const exports = instance.exports;
    if (!(exports.memory instanceof WebAssembly.Memory))
        throw new Error('The participant module has no memory.');
    instantiated.memory = exports.memory;
    // A call that ends without returning, by a trap or by a host function
    // that failed, leaves the instance in an unknown state, so every later
    // call ends with the same failure.
    let ended: { error: unknown } | undefined;
    const module: Record<string, unknown> = { memory: exports.memory };
    for (const name of moduleFunctions) {
        const call = exports[name];
        if (typeof call !== 'function')
            throw new Error('The participant module lacks ' + name + '.');
        module[name] = (...values: number[]): number => {
            if (ended !== undefined) throw ended.error;
            try {
                return (call as ModuleFunction)(...values);
            } catch (error) {
                const failure =
                    error instanceof ResourceFailure
                        ? error
                        : new ModuleFailure(
                              'The participant module failed in ' +
                                  name +
                                  ': ' +
                                  (error instanceof Error
                                      ? error.message
                                      : String(error)),
                          );
                ended = { error: failure };
                throw failure;
            }
        };
    }
    return { module: module as ParticipantModule, handlers };
};

// The module may grow its memory during any call, so every access takes a
// fresh view of the current buffer. A write never exceeds the capacity of
// the module buffer it fills.
const writeModuleMemory = (
    module: ParticipantModule,
    pointer: number,
    bytes: Uint8Array,
    capacity: number,
): void => {
    if (bytes.length > capacity)
        throw new Error('Module input exceeds its buffer.');
    new Uint8Array(module.memory.buffer, pointer >>> 0, bytes.length).set(
        bytes,
    );
};

export const readModuleMemory = (
    module: ParticipantModule,
    pointer: number,
    length: number,
): Uint8Array =>
    new Uint8Array(module.memory.buffer, pointer >>> 0, length >>> 0).slice();

export const writeInput = (module: ParticipantModule, bytes: Uint8Array) =>
    writeModuleMemory(
        module,
        module.input_pointer(),
        bytes,
        module.input_capacity(),
    );

// Writes the setup verifier's input at an offset; a polynomial's previous
// aggregate chunk follows its incoming chunk.
export const writeSetupInput = (
    module: ParticipantModule,
    bytes: Uint8Array,
    offset = 0,
) => {
    const capacity = module.setup_input_capacity();
    if (offset > capacity) throw new Error('Module input exceeds its buffer.');
    writeModuleMemory(
        module,
        module.setup_input_pointer() + offset,
        bytes,
        capacity - offset,
    );
};

// Every private randomness of a contribution generation or continuation, a
// ballot or a release comes from one seed its root retains before the
// operation draws any byte. The module expands the seed into the operation's
// first stream and its proof stream, which serve the operation's draws
// within the module; a release has only the proof stream.
export const operationSeedBytes = 64;
// The randomness commands: each operation's seed installation, and the
// discarding of the installed streams.
const randomOperation = {
    contribution: 0,
    discard: 3,
    ballot: 4,
    release: 5,
} as const;
const proofStream = 1;

// Installs an operation's retained seed, whose streams then serve every
// draw of the operation and refuse any other. The seed must be discarded
// once the operation stops drawing.
export const seededRandomness = (
    module: ParticipantModule,
    purpose: Exclude<keyof typeof randomOperation, 'discard'>,
    seed: Uint8Array,
) => {
    if (seed.length !== operationSeedBytes)
        throw new Error('No ' + purpose + ' randomness seed is retained.');
    writeModuleMemory(
        module,
        module.operation_random_input_pointer(),
        seed,
        operationSeedBytes,
    );
    if (
        module.operation_random_command(
            randomOperation[purpose],
            operationSeedBytes,
        ) !== 0
    )
        throw new Error('The ' + purpose + ' randomness refused its seed.');
    // The module counts each stream's bytes until the next seed is installed.
    const drawn = (stream: number) =>
        module.operation_random_drawn(stream) >>> 0;
    return {
        drawn: () => drawn(0) + drawn(proofStream),
        // The bytes the proof stream served.
        proofDrawn: () => drawn(proofStream),
        discard: () => {
            module.operation_random_command(randomOperation.discard, 0);
        },
    };
};

// The output the last participant command left.
export const readParticipantOutput = (module: ParticipantModule) =>
    readModuleMemory(
        module,
        module.contribution_output_pointer(),
        module.contribution_output_length(),
    );

export const writeProofInput = (module: ParticipantModule, bytes: Uint8Array) =>
    writeModuleMemory(
        module,
        module.contribution_proof_input_pointer(),
        bytes,
        module.contribution_proof_input_capacity(),
    );

// The certificate collector's, close verifier's, ballot classifier's and
// evaluation's input buffers, by the exports that give each one's address
// and the capacity the module reports for it.
const inputBuffers = {
    completion: ['completion_input_pointer', 'completion_input_capacity'],
    close: ['close_input_pointer', 'close_input_capacity'],
    ballotBody: ['ballot_body_input_pointer', 'ballot_body_input_capacity'],
    evaluationTarget: [
        'evaluation_target_input_pointer',
        'evaluation_target_input_capacity',
    ],
} as const;

export const writeBufferInput = (
    module: ParticipantModule,
    buffer: keyof typeof inputBuffers,
    bytes: Uint8Array,
) => {
    const [pointer, capacity] = inputBuffers[buffer];
    writeModuleMemory(module, module[pointer](), bytes, module[capacity]());
};

// Refuses, before an operation starts, a module whose certificate, close,
// classifier or evaluation buffer cannot take the largest input the worker
// writes into it at once.
export const requireInputCapacities = (
    module: ParticipantModule,
    largestInputBytes: number,
) => {
    for (const [buffer, [, capacity]] of Object.entries(inputBuffers))
        if (module[capacity]() < largestInputBytes)
            throw new ModuleFailure(
                'The participant module cannot take the largest input in its ' +
                    buffer +
                    ' buffer.',
            );
};

export const writeOwnRegistrationInput = (
    module: ParticipantModule,
    bytes: Uint8Array,
) =>
    writeModuleMemory(
        module,
        module.own_registration_input_pointer(),
        bytes,
        module.own_registration_input_capacity(),
    );
