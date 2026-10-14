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
    'retain_proposal',
    'retained_proposal_identity_pointer',
    'participant_ballot_command',
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
    // The signed ballot classifier.
    'ballot_body_input_pointer',
    'ballot_body_input_capacity',
    'ballot_classification_begin',
    // One when the body relation needs its encryption keys.
    'ballot_classification_requires_key',
    'ballot_classification_key_begin',
    'ballot_classification_key_chunk',
    'ballot_classification_key_finish',
    'ballot_classification_chunk',
    'ballot_classification_finish',
    // One when the finished classification holds a valid body.
    'ballot_classification_is_valid',
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
    // Writes the authenticated selection to the setup output: its identity,
    // then each selected position as four bytes and its body identity.
    'setup_selection_output',
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
] as const satisfies readonly Exclude<keyof ParticipantModule, 'memory'>[];

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
    contribution_output_pointer: () => number;
    contribution_output_length: () => number;
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
        subject: 'ballot module',
        write: writeInput,
        run: (module, operation, argument, length) =>
            module.participant_ballot_command(operation, argument, length),
        read: readParticipantOutput,
    },
    close: {
        subject: 'close module',
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
        subject: 'original preparation signer',
        write: writeInput,
        run: (module, operation, _argument, length) =>
            module.selection_signing_command(operation, length),
        read: readParticipantOutput,
    },
    offerSigning: {
        subject: 'contribution signer',
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
