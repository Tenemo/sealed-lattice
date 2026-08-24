/** Untrusted pre-protocol poll input accepted by validation helpers. */
export type PollSpecInput = {
    readonly pollId: string;
    readonly question: string;
    readonly options: readonly string[];
    readonly topOptionCount: number;
};

/** Validated poll input whose bounded options can be encoded as a canonical manifest. */
export type PollSpec = PollSpecInput;

/** Stable poll specification validation error code. */
export type PollSpecValidationErrorCode =
    | 'EmptyPollId'
    | 'EmptyQuestion'
    | 'UnsupportedHashCriticalText'
    | 'InvalidOptionCount'
    | 'EmptyOptionLabel'
    | 'DuplicateOptionLabel'
    | 'InvalidTopOptionCount';

/** Structured poll specification validation error. */
export type PollSpecValidationError = {
    readonly code: PollSpecValidationErrorCode;
    readonly field: string;
    readonly message: string;
};

/** Poll specification validation result with normalized output or errors. */
export type PollSpecValidation =
    | {
          readonly isValid: true;
          readonly normalized: PollSpec;
      }
    | {
          readonly isValid: false;
          readonly errors: readonly PollSpecValidationError[];
      };
