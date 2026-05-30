export type FailureExpectation = {
    readonly description: string;
    readonly pattern: RegExp;
};

export const expectedVerifierFailure = (
    description: string,
    pattern: RegExp,
): FailureExpectation => ({
    description,
    pattern,
});

const verifierFailureDiagnostics = (failure: {
    readonly refusedObjects?: unknown;
    readonly statusLabels?: unknown;
    readonly unresolvedReason?: unknown;
}): readonly string[] => {
    const diagnostics: string[] = [];
    if (typeof failure.unresolvedReason === 'string') {
        diagnostics.push(failure.unresolvedReason);
    }
    if (Array.isArray(failure.statusLabels)) {
        diagnostics.push(
            ...failure.statusLabels.flatMap((statusLabel) =>
                typeof statusLabel === 'string' ? [statusLabel] : [],
            ),
        );
    }
    if (Array.isArray(failure.refusedObjects)) {
        for (const refusedObject of failure.refusedObjects) {
            if (typeof refusedObject === 'string') {
                diagnostics.push(refusedObject);
            } else if (
                typeof refusedObject === 'object' &&
                refusedObject !== null
            ) {
                const refusal = refusedObject as {
                    readonly code?: unknown;
                    readonly message?: unknown;
                    readonly object?: unknown;
                    readonly path?: unknown;
                };
                for (const value of [
                    refusal.code,
                    refusal.message,
                    refusal.object,
                    refusal.path,
                ]) {
                    if (typeof value === 'string') {
                        diagnostics.push(value);
                    }
                }
            }
        }
    }

    return diagnostics;
};

// Inverted "null-is-good" contract that the whole negative matrix relies on: returns
// null only when the expected rejection WAS observed (the matching pattern fired), and
// a diagnostic string on every other path (unexpected pass, wrong diagnostic, throw).
export const assertFailure = (
    action: () => unknown,
    expectation: FailureExpectation,
): string | null => {
    try {
        const result = action();
        if (
            typeof result === 'object' &&
            result !== null &&
            'ok' in result &&
            (result as { readonly ok?: unknown }).ok === false
        ) {
            const failure = result as {
                readonly refusedObjects?: unknown;
                readonly statusLabels?: unknown;
                readonly unresolvedReason?: unknown;
            };
            const diagnostics = verifierFailureDiagnostics(failure);
            if (diagnostics.length === 0) {
                return 'mutation returned ok:false without verifier refusal metadata';
            }
            if (
                diagnostics.some((diagnostic) =>
                    expectation.pattern.test(diagnostic),
                )
            ) {
                return null;
            }

            return `mutation failed with unexpected verifier diagnostic for ${expectation.description}: ${diagnostics.join(' | ')}`;
        }

        return 'mutation unexpectedly passed';
    } catch (error) {
        return `mutation threw a harness exception: ${
            error instanceof Error ? error.message : String(error)
        }`;
    }
};
