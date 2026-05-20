type ProcessMemoryUsage = {
    readonly arrayBuffers?: number;
    readonly external?: number;
    readonly heapTotal?: number;
    readonly heapUsed?: number;
    readonly rss?: number;
};

type ProcessLike = {
    readonly memoryUsage?: () => ProcessMemoryUsage;
};

type PerformanceMemory = {
    readonly jsHeapSizeLimit?: number;
    readonly totalJSHeapSize?: number;
    readonly usedJSHeapSize?: number;
};

type PerformanceWithMemory = Performance & {
    readonly memory?: PerformanceMemory;
};

export type RuntimeMemorySnapshot = {
    readonly arrayBufferBytes?: number;
    readonly externalBytes?: number;
    readonly heapLimitBytes?: number;
    readonly residentSetBytes?: number;
    readonly totalHeapBytes?: number;
    readonly usedHeapBytes?: number;
};

const safeMemoryInteger = (value: number | undefined): number | undefined =>
    value === undefined || !Number.isSafeInteger(value) || value < 0
        ? undefined
        : value;

export const captureRuntimeMemorySnapshot = (): RuntimeMemorySnapshot => {
    const performanceMemory = (
        globalThis.performance as PerformanceWithMemory | undefined
    )?.memory;
    if (performanceMemory !== undefined) {
        return {
            heapLimitBytes: safeMemoryInteger(
                performanceMemory.jsHeapSizeLimit,
            ),
            totalHeapBytes: safeMemoryInteger(
                performanceMemory.totalJSHeapSize,
            ),
            usedHeapBytes: safeMemoryInteger(performanceMemory.usedJSHeapSize),
        };
    }

    const processLike = (globalThis as { readonly process?: ProcessLike })
        .process;
    const memoryUsage = processLike?.memoryUsage?.();

    return memoryUsage === undefined
        ? {}
        : {
              arrayBufferBytes: safeMemoryInteger(memoryUsage.arrayBuffers),
              externalBytes: safeMemoryInteger(memoryUsage.external),
              residentSetBytes: safeMemoryInteger(memoryUsage.rss),
              totalHeapBytes: safeMemoryInteger(memoryUsage.heapTotal),
              usedHeapBytes: safeMemoryInteger(memoryUsage.heapUsed),
          };
};
