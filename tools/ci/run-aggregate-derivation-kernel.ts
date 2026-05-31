import { main } from './aggregate-derivation-kernel/runner.js';

main().catch((error: unknown) => {
    console.error(error);
    process.exitCode = 1;
});
