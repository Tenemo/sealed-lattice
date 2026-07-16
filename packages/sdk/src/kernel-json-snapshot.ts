const maximumKernelInputValueCount = 1_000_000;
const maximumKernelInputNestingDepth = 64;

export type KernelJsonSnapshotState = {
    valueCount: number;
};

export const createKernelJsonSnapshotState = (): KernelJsonSnapshotState => ({
    valueCount: 0,
});

export const chargeKernelJsonSnapshotValues = (
    state: KernelJsonSnapshotState,
    additionalValueCount: number,
): void => {
    if (
        additionalValueCount < 0 ||
        !Number.isSafeInteger(additionalValueCount) ||
        additionalValueCount > maximumKernelInputValueCount - state.valueCount
    ) {
        throw new RangeError(
            'The kernel input exceeds the accepted value count.',
        );
    }
    state.valueCount += additionalValueCount;
};

export const snapshotKernelJsonValue = (
    value: unknown,
    valuePath: string,
    state: KernelJsonSnapshotState,
): unknown => {
    const activeObjects = new Set<object>();

    const chargeValue = (
        currentValue: unknown,
        currentPath: string,
        nestingDepth: number,
    ): void => {
        if (nestingDepth > maximumKernelInputNestingDepth) {
            throw new RangeError(
                `${currentPath} exceeds the accepted nesting depth.`,
            );
        }
        chargeKernelJsonSnapshotValues(state, 1);
        if (typeof currentValue !== 'object' || currentValue === null) {
            return;
        }
        if (activeObjects.has(currentValue)) {
            throw new TypeError(`${currentPath} cannot contain a cycle.`);
        }

        activeObjects.add(currentValue);
        try {
            const descriptors = Object.getOwnPropertyDescriptors(currentValue);
            for (const propertyName of Object.keys(descriptors)) {
                const descriptor = descriptors[propertyName];
                if (
                    descriptor === undefined ||
                    descriptor.enumerable !== true
                ) {
                    continue;
                }
                const propertyPath = `${currentPath}.${propertyName}`;
                if ('get' in descriptor || 'set' in descriptor) {
                    throw new TypeError(
                        `${propertyPath} cannot be an accessor property.`,
                    );
                }
                chargeValue(descriptor.value, propertyPath, nestingDepth + 1);
            }
        } finally {
            activeObjects.delete(currentValue);
        }
    };

    chargeValue(value, valuePath, 0);
    return structuredClone(value);
};

export const plainRecordDescriptors = (
    value: unknown,
    valuePath: string,
): PropertyDescriptorMap => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${valuePath} must be a plain object.`);
    }

    return Object.getOwnPropertyDescriptors(value);
};

export const dataPropertyValue = (
    descriptors: PropertyDescriptorMap,
    fieldName: string,
    fieldPath: string,
): unknown => {
    const descriptor = descriptors[fieldName];
    if (descriptor === undefined) {
        return undefined;
    }
    if ('get' in descriptor || 'set' in descriptor) {
        throw new TypeError(`${fieldPath} cannot be an accessor property.`);
    }

    return descriptor.value;
};

export const ordinaryArrayDescriptors = (
    value: unknown,
    valuePath: string,
): Readonly<{
    readonly descriptors: PropertyDescriptorMap;
    readonly length: number;
}> => {
    if (!Array.isArray(value)) {
        throw new TypeError(`${valuePath} must be an array.`);
    }
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    if (
        lengthDescriptor === undefined ||
        !('value' in lengthDescriptor) ||
        !Number.isSafeInteger(lengthDescriptor.value) ||
        lengthDescriptor.value < 0 ||
        lengthDescriptor.value > maximumKernelInputValueCount
    ) {
        throw new RangeError(`${valuePath} exceeds the accepted array length.`);
    }

    return {
        descriptors: Object.getOwnPropertyDescriptors(
            value,
        ) as unknown as PropertyDescriptorMap,
        length: lengthDescriptor.value as number,
    };
};
