import {
    openFoundationCeremonyRuntime,
    type FoundationCeremonyRuntime,
} from '../foundation-ceremony-runtime.js';

import type { FoundationKernelLoaderOptions } from './kernel-runtime.js';
import { instantiateFoundationKernelCommandRuntime } from './kernel-runtime.js';

const createCachedLoader = <Value>(
    load: () => Promise<Value>,
): (() => Promise<Value>) => {
    let valuePromise: Promise<Value> | undefined;
    return async (): Promise<Value> => {
        valuePromise ??= load().catch((error: unknown) => {
            valuePromise = undefined;
            throw error;
        });
        return valuePromise;
    };
};

export const createFoundationCeremonyRuntimeLoader = (
    foundationKernelUrl: URL,
    options: FoundationKernelLoaderOptions = {},
): (() => Promise<FoundationCeremonyRuntime>) =>
    createCachedLoader(async () =>
        openFoundationCeremonyRuntime(
            await instantiateFoundationKernelCommandRuntime(
                foundationKernelUrl,
                options,
            ),
        ),
    );
