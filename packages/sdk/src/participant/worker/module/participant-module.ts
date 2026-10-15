import { ModuleFailure, ResourceFailure } from '../shared/failures.js';

import type { ParallelHelpers } from './parallel-helpers.js';

// The participant scalar module's exports that the worker calls, each with
// its parameter count. Every command returns zero when it accepts and one
// when it refuses, and a query's comment states its answer; the owning Rust
// state machine decides acceptance.
export const moduleArity = {
    // The shared bounds and one profile's, each written as 64-bit words; a
    // command returns the word count, zero for an unsupported profile.
    participant_bounds_pointer: 0,
    participant_limits: 0,
    participant_profile_bounds: 2,
    // The highest linear-memory address any allocation has reached.
    linear_memory_high_water: 0,
    // The bounds of the memory plan of an operation with a helper count,
    // which evaluates the ranking program when the flag is one; zero
    // without a plan. Reserve lowers the instance's bound to the worker's
    // share before its first allocation.
    helper_memory_bound: 2,
    worker_memory_bound: 2,
    worker_reserve: 2,
    input_pointer: 0,
    input_capacity: 0,
    poll_identity_pointer: 0,
    validate_organizer: 1,
    validate_joiner: 1,
    prepare_organizer: 1,
    prepare_joiner: 1,
    restore: 1,
    restore_prepared: 1,
    retire_contribution_sources: 0,
    own_registration_input_pointer: 0,
    own_registration_input_capacity: 0,
    own_registration_command: 2,
    own_registration_body_digest_pointer: 0,
    own_registration_username_pointer: 0,
    own_registration_username_length: 0,
    // The verified poll's option count, or zero before verification.
    own_registration_option_count: 0,
    // The verified poll's participant maximum, or zero before verification.
    own_registration_maximum_participants: 0,
    // Writes the verified poll's result length, question and options to the
    // contribution output.
    own_registration_poll: 0,
    roster_begin: 1,
    // The registration records the worker may stream at once.
    roster_open_records: 0,
    roster_record: 3,
    roster_finish: 0,
    roster_body_pointer: 0,
    roster_body_length: 0,
    roster_identity_pointer: 0,
    // Writes the verified proposal's usernames in roster order to the
    // contribution output, each as its four-byte length and its bytes.
    roster_usernames: 0,
    validate_roster_signer: 0,
    sign_roster_proposal: 1,
    roster_signature_pointer: 0,
    verify_roster_signature: 1,
    retain_proposal: 1,
    retained_proposal_identity_pointer: 0,
    participant_ballot_command: 3,
    participant_close_command: 3,
    participant_finality_command: 2,
    participant_release_command: 2,
    // The inventory certificate, release contexts and release shares.
    completion_input_pointer: 0,
    completion_input_capacity: 0,
    completion_output_pointer: 0,
    completion_output_length: 0,
    completion_command: 3,
    // The public close barrier verifier.
    close_input_pointer: 0,
    close_input_capacity: 0,
    close_command: 2,
    close_missing_pointer: 0,
    close_missing_count: 0,
    // The signed ballot classifier.
    ballot_body_input_pointer: 0,
    ballot_body_input_capacity: 0,
    ballot_classification_begin: 1,
    // One when the body relation needs its encryption keys.
    ballot_classification_requires_key: 0,
    ballot_classification_key_begin: 1,
    ballot_classification_key_chunk: 1,
    ballot_classification_key_finish: 0,
    ballot_classification_chunk: 1,
    ballot_classification_finish: 0,
    // One when the finished classification holds a valid body.
    ballot_classification_is_valid: 0,
    // The public ranking evaluation.
    evaluation_target_input_pointer: 0,
    evaluation_target_input_capacity: 0,
    evaluation_target_output_pointer: 0,
    evaluation_target_output_length: 0,
    evaluation_target_command: 3,
    evaluation_target_body_pointer: 0,
    evaluation_target_body_length: 0,
    // One when every evaluation step has run.
    evaluation_target_finished: 0,
    // The evaluated target keyed to the credential, and its restoration:
    // zero begins a copy of a length, one appends input bytes and two
    // restores it.
    retain_evaluation: 0,
    restore_evaluation: 2,
    confirm_roster: 0,
    offer_signing_command: 3,
    selection_signing_command: 2,
    retain_selection_inputs: 0,
    restore_selection_inputs: 1,
    participant_output_pointer: 0,
    participant_output_length: 0,
    begin_contribution: 1,
    contribution_proof_input_pointer: 0,
    contribution_proof_input_capacity: 0,
    contribution_proof_command: 3,
    contribution_proof_phase: 0,
    contribution_proof_output_pointer: 0,
    contribution_proof_output_length: 0,
    contribution_checkpoint_records: 0,
    contribution_checkpoint_command: 3,
    contribution_checkpoint_key: 2,
    // The randomness of a contribution generation or continuation, a ballot
    // or a release, expanded from the seed its root retains.
    operation_random_input_pointer: 0,
    operation_random_command: 2,
    operation_random_drawn: 1,
    setup_input_pointer: 0,
    setup_input_capacity: 0,
    setup_chunk_capacity: 0,
    setup_roster_begin: 1,
    setup_roster_record: 3,
    setup_roster_finish: 1,
    // The verified roster's poll option count, or zero before it verifies.
    setup_option_count: 0,
    setup_output_pointer: 0,
    setup_output_length: 0,
    setup_offer_begin: 1,
    setup_public_work: 4,
    setup_public_output_pointer: 0,
    setup_public_output_length: 0,
    setup_inputs_available: 0,
    setup_offer_polynomial: 3,
    setup_offer_proof: 2,
    setup_offer_finish: 0,
    // One when a verified offer has the position and body identity.
    setup_offer_available: 2,
    setup_selection_build: 1,
    setup_selection_begin: 1,
    // Writes the authenticated selection to the setup output: its identity,
    // then each selected position as four bytes and its body identity.
    setup_selection_output: 0,
    setup_selection_aggregate: 0,
    setup_begin_selected_offer: 1,
    setup_begin_selected_offer_verification: 1,
    setup_polynomial: 3,
    setup_selected_offer_proof: 2,
    setup_finish_selected_offer: 0,
    setup_accepted: 0,
    setup_selection_finish: 0,
    setup_discard_aggregation: 0,
    setup_endorsement: 1,
    setup_certificate_build: 0,
    setup_certificate: 1,
    setup_finish_certificate: 0,
    retain_setup: 0,
    // Restores the verified setup from the retained setup reference.
    restore_setup: 1,
    // The identities the runtime binds into its retained state.
    custody_identity_input_pointer: 0,
    custody_identity_input_capacity: 0,
    custody_identity_output_pointer: 0,
    custody_identity_begin: 2,
    custody_identity_absorb: 1,
    custody_identity_finish: 0,
} as const satisfies {
    readonly [Name in Exclude<keyof ParticipantModule, 'memory'>]: Parameters<
        ParticipantModule[Name]
    >['length'];
};

export const moduleFunctions = Object.keys(
    moduleArity,
) as readonly (keyof typeof moduleArity)[];

type ModuleFunction = (...values: number[]) => number;
export type ParticipantModule = Readonly<{
    memory: WebAssembly.Memory;
    participant_bounds_pointer: () => number;
    participant_limits: () => number;
    participant_profile_bounds: (
        participants: number,
        options: number,
    ) => number;
    linear_memory_high_water: () => number;
    helper_memory_bound: (helpers: number, evaluation: number) => number;
    worker_memory_bound: (helpers: number, evaluation: number) => number;
    worker_reserve: (helpers: number, evaluation: number) => number;
    input_pointer: () => number;
    input_capacity: () => number;
    poll_identity_pointer: () => number;
    validate_organizer: (length: number) => number;
    validate_joiner: (length: number) => number;
    prepare_organizer: (length: number) => number;
    prepare_joiner: (length: number) => number;
    restore: (length: number) => number;
    restore_prepared: (length: number) => number;
    retire_contribution_sources: () => number;
    own_registration_input_pointer: () => number;
    own_registration_input_capacity: () => number;
    own_registration_command: (operation: number, length: number) => number;
    own_registration_body_digest_pointer: () => number;
    own_registration_username_pointer: () => number;
    own_registration_username_length: () => number;
    own_registration_option_count: () => number;
    own_registration_maximum_participants: () => number;
    own_registration_poll: () => number;
    roster_begin: (length: number) => number;
    roster_open_records: () => number;
    roster_record: (
        operation: number,
        position: number,
        length: number,
    ) => number;
    roster_finish: () => number;
    roster_body_pointer: () => number;
    roster_body_length: () => number;
    roster_identity_pointer: () => number;
    roster_usernames: () => number;
    validate_roster_signer: () => number;
    sign_roster_proposal: (length: number) => number;
    roster_signature_pointer: () => number;
    verify_roster_signature: (length: number) => number;
    retain_proposal: (length: number) => number;
    retained_proposal_identity_pointer: () => number;
    participant_ballot_command: (
        operation: number,
        argument: number,
        length: number,
    ) => number;
    participant_close_command: (
        operation: number,
        argument: number,
        length: number,
    ) => number;
    participant_finality_command: (operation: number, length: number) => number;
    participant_release_command: (operation: number, length: number) => number;
    completion_input_pointer: () => number;
    completion_input_capacity: () => number;
    completion_output_pointer: () => number;
    completion_output_length: () => number;
    completion_command: (
        operation: number,
        argument: number,
        length: number,
    ) => number;
    close_input_pointer: () => number;
    close_input_capacity: () => number;
    close_command: (operation: number, length: number) => number;
    close_missing_pointer: () => number;
    close_missing_count: () => number;
    ballot_body_input_pointer: () => number;
    ballot_body_input_capacity: () => number;
    ballot_classification_begin: (length: number) => number;
    ballot_classification_requires_key: () => number;
    ballot_classification_key_begin: (index: number) => number;
    ballot_classification_key_chunk: (length: number) => number;
    ballot_classification_key_finish: () => number;
    ballot_classification_chunk: (length: number) => number;
    ballot_classification_finish: () => number;
    ballot_classification_is_valid: () => number;
    evaluation_target_input_pointer: () => number;
    evaluation_target_input_capacity: () => number;
    evaluation_target_output_pointer: () => number;
    evaluation_target_output_length: () => number;
    evaluation_target_command: (
        operation: number,
        argument: number,
        length: number,
    ) => number;
    evaluation_target_body_pointer: () => number;
    evaluation_target_body_length: () => number;
    evaluation_target_finished: () => number;
    retain_evaluation: () => number;
    restore_evaluation: (operation: number, length: number) => number;
    confirm_roster: () => number;
    offer_signing_command: (
        operation: number,
        argument: number,
        length: number,
    ) => number;
    selection_signing_command: (operation: number, length: number) => number;
    retain_selection_inputs: () => number;
    restore_selection_inputs: (length: number) => number;
    participant_output_pointer: () => number;
    participant_output_length: () => number;
    begin_contribution: (position: number) => number;
    contribution_proof_input_pointer: () => number;
    contribution_proof_input_capacity: () => number;
    contribution_proof_command: (
        operation: number,
        argument: number,
        length: number,
    ) => number;
    contribution_proof_phase: () => number;
    contribution_proof_output_pointer: () => number;
    contribution_proof_output_length: () => number;
    contribution_checkpoint_records: () => number;
    contribution_checkpoint_command: (
        operation: number,
        position: number,
        length: number,
    ) => number;
    contribution_checkpoint_key: (position: number, length: number) => number;
    operation_random_input_pointer: () => number;
    operation_random_command: (operation: number, length: number) => number;
    operation_random_drawn: (stream: number) => number;
    setup_input_pointer: () => number;
    setup_input_capacity: () => number;
    setup_chunk_capacity: () => number;
    setup_roster_begin: (length: number) => number;
    setup_roster_record: (
        operation: number,
        position: number,
        length: number,
    ) => number;
    setup_roster_finish: (length: number) => number;
    setup_option_count: () => number;
    setup_output_pointer: () => number;
    setup_output_length: () => number;
    setup_offer_begin: (length: number) => number;
    setup_public_work: (
        operation: number,
        index: number,
        offset: number,
        length: number,
    ) => number;
    setup_public_output_pointer: () => number;
    setup_public_output_length: () => number;
    setup_inputs_available: () => number;
    setup_offer_polynomial: (
        index: number,
        offset: number,
        length: number,
    ) => number;
    setup_offer_proof: (offset: number, length: number) => number;
    setup_offer_finish: () => number;
    setup_offer_available: (position: number, length: number) => number;
    setup_selection_build: (length: number) => number;
    setup_selection_begin: (length: number) => number;
    setup_selection_output: () => number;
    setup_selection_aggregate: () => number;
    setup_begin_selected_offer: (position: number) => number;
    setup_begin_selected_offer_verification: (length: number) => number;
    setup_polynomial: (index: number, offset: number, length: number) => number;
    setup_selected_offer_proof: (offset: number, length: number) => number;
    setup_finish_selected_offer: () => number;
    setup_accepted: () => number;
    setup_selection_finish: () => number;
    setup_discard_aggregation: () => number;
    setup_endorsement: (length: number) => number;
    setup_certificate_build: () => number;
    setup_certificate: (length: number) => number;
    setup_finish_certificate: () => number;
    retain_setup: () => number;
    restore_setup: (length: number) => number;
    custody_identity_input_pointer: () => number;
    custody_identity_input_capacity: () => number;
    custody_identity_output_pointer: () => number;
    custody_identity_begin: (purpose: number, length: number) => number;
    custody_identity_absorb: (length: number) => number;
    custody_identity_finish: () => number;
}>;

export type ModuleHandlers = {
    random?: (target: Uint8Array<ArrayBuffer>) => void;
    staged?: (kind: number, offset: number, bytes: Uint8Array) => void;
    contribution?: (object: number, offset: number, bytes: Uint8Array) => void;
};

// Randomness requests are bounded before any view of module memory exists.
const maximumRandomRequest = 65_536;

type LoadedModule = Readonly<{
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
        // A missing argument would reach the module as zero, so an export
        // must take exactly the parameters the worker passes.
        if (call.length !== moduleArity[name])
            throw new Error(
                'The participant module export ' +
                    name +
                    ' takes ' +
                    String(call.length) +
                    ' parameters, not ' +
                    String(moduleArity[name]) +
                    '.',
            );
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
    return {
        // The bytes the proof stream served, which the module counts until
        // the next seed is installed.
        proofDrawn: () => module.operation_random_drawn(proofStream) >>> 0,
        discard: () => {
            module.operation_random_command(randomOperation.discard, 0);
        },
    };
};

// The output the last participant command left.
export const readParticipantOutput = (module: ParticipantModule) =>
    readModuleMemory(
        module,
        module.participant_output_pointer(),
        module.participant_output_length(),
    );

export const writeProofInput = (module: ParticipantModule, bytes: Uint8Array) =>
    writeModuleMemory(
        module,
        module.contribution_proof_input_pointer(),
        bytes,
        module.contribution_proof_input_capacity(),
    );

// The completion verifier's, close barrier verifier's, ballot classifier's
// and evaluation's input buffers, by the exports that give each one's address
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

// The module's command dispatchers. Each takes its input in one buffer, runs
// an operation with the operation's argument, when it takes one, and the
// input length, answers zero when it accepts, and leaves the output its
// callers read. A refusal names the dispatcher's subject.
type CommandDispatcher = Readonly<{
    subject: string;
    write: (module: ParticipantModule, bytes: Uint8Array) => void;
    run: (
        module: ParticipantModule,
        operation: number,
        argument: number,
        length: number,
    ) => number;
    read: (module: ParticipantModule) => Uint8Array;
}>;
const noOutput = () => new Uint8Array();
const commandDispatchers = {
    ballot: {
        subject: 'ballot work',
        write: writeInput,
        run: (module, operation, argument, length) =>
            module.participant_ballot_command(operation, argument, length),
        read: readParticipantOutput,
    },
    close: {
        subject: 'close work',
        write: writeInput,
        run: (module, operation, argument, length) =>
            module.participant_close_command(operation, argument, length),
        read: readParticipantOutput,
    },
    finality: {
        subject: 'finality work',
        write: writeInput,
        run: (module, operation, _argument, length) =>
            module.participant_finality_command(operation, length),
        read: readParticipantOutput,
    },
    release: {
        subject: 'release work',
        write: writeInput,
        run: (module, operation, _argument, length) =>
            module.participant_release_command(operation, length),
        read: readParticipantOutput,
    },
    selection: {
        subject: 'selection signer',
        write: writeInput,
        run: (module, operation, _argument, length) =>
            module.selection_signing_command(operation, length),
        read: readParticipantOutput,
    },
    offerSigning: {
        subject: 'offer signer',
        write: writeInput,
        run: (module, operation, argument, length) =>
            module.offer_signing_command(operation, argument, length),
        read: readParticipantOutput,
    },
    contributionProof: {
        subject: 'contribution prover',
        write: writeProofInput,
        run: (module, operation, argument, length) =>
            module.contribution_proof_command(operation, argument, length),
        read: noOutput,
    },
    contributionCheckpoint: {
        subject: 'contribution checkpoint',
        write: writeProofInput,
        run: (module, operation, argument, length) =>
            module.contribution_checkpoint_command(operation, argument, length),
        read: noOutput,
    },
    ownRegistration: {
        subject: 'original registration verification',
        write: writeOwnRegistrationInput,
        run: (module, operation, _argument, length) =>
            module.own_registration_command(operation, length),
        read: noOutput,
    },
    closeBarrier: {
        subject: 'close barrier',
        write: (module, bytes) => {
            writeBufferInput(module, 'close', bytes);
        },
        run: (module, operation, _argument, length) =>
            module.close_command(operation, length),
        read: noOutput,
    },
    evaluation: {
        subject: 'evaluation',
        write: (module, bytes) => {
            writeBufferInput(module, 'evaluationTarget', bytes);
        },
        run: (module, operation, argument, length) =>
            module.evaluation_target_command(operation, argument, length),
        read: (module) =>
            readModuleMemory(
                module,
                module.evaluation_target_output_pointer(),
                module.evaluation_target_output_length(),
            ),
    },
    completion: {
        subject: 'completion',
        write: (module, bytes) => {
            writeBufferInput(module, 'completion', bytes);
        },
        run: (module, operation, argument, length) =>
            module.completion_command(operation, argument, length),
        read: (module) =>
            readModuleMemory(
                module,
                module.completion_output_pointer(),
                module.completion_output_length(),
            ),
    },
} as const satisfies Record<string, CommandDispatcher>;
type CommandOptions = Readonly<{ argument?: number; input?: Uint8Array }>;

// Runs one command: the output it left, or undefined when the module refused
// it.
export const tryModuleCommand = (
    module: ParticipantModule,
    dispatcher: keyof typeof commandDispatchers,
    operation: number,
    { argument = 0, input = new Uint8Array() }: CommandOptions = {},
) => {
    const { write, run, read } = commandDispatchers[dispatcher];
    write(module, input);
    return run(module, operation, argument, input.length) === 0
        ? read(module)
        : undefined;
};

// Runs one command whose refusal is a local failure.
export const moduleCommand = (
    module: ParticipantModule,
    dispatcher: keyof typeof commandDispatchers,
    operation: number,
    options: CommandOptions = {},
) => {
    const output = tryModuleCommand(module, dispatcher, operation, options);
    if (output === undefined)
        throw new Error(
            'The ' +
                commandDispatchers[dispatcher].subject +
                ' refused operation ' +
                String(operation) +
                '.',
        );
    return output;
};
