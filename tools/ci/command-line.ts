import { fileURLToPath } from 'node:url';

// The repository root, against which the tools resolve repository paths.
export const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));

// A tool's arguments without the `--` that `pnpm run <script> --` can pass
// before them.
export const toolArguments = (
    commandLineArguments: readonly string[],
): readonly string[] =>
    commandLineArguments[0] === '--'
        ? commandLineArguments.slice(1)
        : commandLineArguments;
