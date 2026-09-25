// The participant scalar module's exports that the worker calls. A command
// returns zero on success unless its comment says otherwise; the owning Rust
// state machine decides acceptance.
const kernelFunctions = [
    'input_pointer',
    'input_capacity',
    'poll_identity_pointer',
    'validate_creator',
    'validate_join',
    'prepare_creator',
    'prepare_join',
    'restore',
    'check_retained',
    'own_registration_input_pointer',
    'own_registration_input_capacity',
    'own_registration_command',
    'own_registration_proof_hash_pointer',
    'own_registration_body_digest_pointer',
    'own_registration_username_pointer',
    'own_registration_username_length',
    'roster_begin',
    'roster_record_begin',
    'roster_record_key',
    'roster_record_key_finish',
    'roster_record_proof',
    'roster_record_finish',
    // One when the proposal is complete.
    'roster_finish',
    'roster_body_pointer',
    'roster_body_length',
    'roster_identity_pointer',
    'validate_roster_signer',
    'sign_roster_proposal',
    'roster_signature_pointer',
    // One when the signature verifies.
    'verify_roster_signature',
    'retain_proposal',
    'retained_proposal_identity_pointer',
    'participant_ballot_command',
    'participant_ballot_key_index',
    'participant_close_command',
    'participant_finality_command',
    'participant_release_command',
    // The release journal's entropy queue.
    'release_entropy_input_pointer',
    'release_entropy_output_pointer',
    'release_entropy_command',
    // The target certificate, release contexts and release shares.
    'completion_input_pointer',
    'completion_output_pointer',
    'completion_output_length',
    'completion_command',
    // The public close barrier verifier.
    'close_input_pointer',
    'close_command',
    'close_missing_pointer',
    'close_missing_count',
    // The signed ballot classifier. Finish returns one for a valid body, two
    // for an invalid one and zero when classification refused.
    'ballot_body_input_pointer',
    'ballot_classification_begin',
    // One when the body relation needs its encryption keys.
    'ballot_classification_requires_keys',
    'ballot_classification_key_begin',
    'ballot_classification_key_chunk',
    'ballot_classification_key_finish',
    'ballot_classification_chunk',
    'ballot_classification_finish',
    // The public ranking evaluation.
    'evaluation_target_input_pointer',
    'evaluation_target_output_pointer',
    'evaluation_target_output_length',
    'evaluation_target_command',
    'evaluation_target_body_pointer',
    'evaluation_target_body_length',
    'evaluation_target_ciphertext_length',
    // One when every evaluation step has run.
    'evaluation_target_finished',
    'contribution_signing',
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
    'setup_input_pointer',
    'setup_input_capacity',
    'setup_chunk_capacity',
    'setup_roster_begin',
    'setup_roster_record',
    // One when the organizer's proposal verifies.
    'setup_roster_finish',
    'setup_confirmation',
    // One when every confirmation is known.
    'setup_inventory_finish',
    'setup_begin_opening',
    'setup_polynomial',
    'setup_proof',
    // One when the contribution is accepted.
    'setup_finish_contribution',
    'setup_accepted',
    // One when the setup is complete.
    'setup_finish',
    'setup_inventory_pointer',
    'retain_setup',
    // The identities the runtime binds into its retained state.
    'custody_identity_input_pointer',
    'custody_identity_input_capacity',
    'custody_identity_output_pointer',
    'custody_identity_begin',
    'custody_identity_absorb',
    'custody_identity_finish',
] as const;

type KernelFunction = (...values: number[]) => number;
export type ParticipantKernel = Readonly<
    Record<(typeof kernelFunctions)[number], KernelFunction> & {
        memory: WebAssembly.Memory;
    }
>;

// The randomness each import draws: registration and credential generation,
// contribution witnesses, proofs, and ballot encryption.
type RandomSource = 'enrollment' | 'witness' | 'proof' | 'ballot';

export type KernelHandlers = {
    random?: (source: RandomSource, target: Uint8Array<ArrayBuffer>) => void;
    staged?: (kind: number, offset: number, bytes: Uint8Array) => void;
    contribution?: (object: number, offset: number, bytes: Uint8Array) => void;
};

// Randomness requests are bounded before any view of module memory exists.
const maximumRandomRequest = 65_536;

export type LoadedKernel = Readonly<{
    kernel: ParticipantKernel;
    // Handlers for the current operation; an absent handler refuses.
    handlers: KernelHandlers;
}>;

export const instantiateParticipantKernel = async (
    module: WebAssembly.Module,
): Promise<LoadedKernel> => {
    const handlers: KernelHandlers = {};
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
    const random =
        (source: RandomSource) => (pointer: number, length: number) => {
            if (handlers.random === undefined || length > maximumRandomRequest)
                throw new Error('Unexpected participant randomness request.');
            handlers.random(source, view(pointer, length));
            return 0;
        };
    const instance = await WebAssembly.instantiate(module, {
        enrollment: {
            fill_random: random('enrollment'),
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
        setup_witness: { fill_random: random('witness') },
        word_proof: { fill_random: random('proof') },
        ballot: { fill_random: random('ballot') },
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
    for (const name of kernelFunctions)
        if (typeof exports[name] !== 'function')
            throw new Error('The participant module lacks ' + name + '.');
    return { kernel: exports as unknown as ParticipantKernel, handlers };
};

// The module may grow its memory during any call, so every access takes a
// fresh view of the current buffer. A write never exceeds the capacity of
// the module buffer it fills.
const writeKernel = (
    kernel: ParticipantKernel,
    pointer: number,
    bytes: Uint8Array,
    capacity: number,
): void => {
    if (bytes.length > capacity)
        throw new Error('Module input exceeds its buffer.');
    new Uint8Array(kernel.memory.buffer, pointer >>> 0, bytes.length).set(
        bytes,
    );
};

export const readKernel = (
    kernel: ParticipantKernel,
    pointer: number,
    length: number,
): Uint8Array =>
    new Uint8Array(kernel.memory.buffer, pointer >>> 0, length >>> 0).slice();

export const writeInput = (kernel: ParticipantKernel, bytes: Uint8Array) =>
    writeKernel(kernel, kernel.input_pointer(), bytes, kernel.input_capacity());

// Writes the setup verifier's input at an offset; a polynomial's previous
// aggregate chunk follows its incoming chunk.
export const writeSetupInput = (
    kernel: ParticipantKernel,
    bytes: Uint8Array,
    offset = 0,
) => {
    const capacity = kernel.setup_input_capacity();
    if (offset > capacity) throw new Error('Module input exceeds its buffer.');
    writeKernel(
        kernel,
        kernel.setup_input_pointer() + offset,
        bytes,
        capacity - offset,
    );
};

export const writeProofInput = (kernel: ParticipantKernel, bytes: Uint8Array) =>
    writeKernel(
        kernel,
        kernel.contribution_proof_input_pointer(),
        bytes,
        kernel.contribution_proof_input_capacity(),
    );

// The close verifier, ballot classifier and evaluation each read one input
// buffer of a mebibyte.
export const moduleChunkBytes = 1 << 20;

export const writeChunkInput = (
    kernel: ParticipantKernel,
    pointer: number,
    bytes: Uint8Array,
) => writeKernel(kernel, pointer, bytes, moduleChunkBytes);

export const writeOwnRegistrationInput = (
    kernel: ParticipantKernel,
    bytes: Uint8Array,
) =>
    writeKernel(
        kernel,
        kernel.own_registration_input_pointer(),
        bytes,
        kernel.own_registration_input_capacity(),
    );
