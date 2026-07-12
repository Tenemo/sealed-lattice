const maximumKernelJsonSnapshotContainerDepth = 64;
const maximumKernelJsonSnapshotValueCount = 1_000_000;
const maximumKernelJsonSnapshotStringCodeUnitCount = 64 * 1024 * 1024;
const omittedKernelJsonObjectProperty = Symbol(
    'omittedKernelJsonObjectProperty',
);

export type KernelJsonSnapshotState = {
    readonly activeContainers: WeakSet<object>;
    stringCodeUnitCount: number;
    valueCount: number;
};

export const createKernelJsonSnapshotState = (): KernelJsonSnapshotState => ({
    activeContainers: new WeakSet<object>(),
    stringCodeUnitCount: 0,
    valueCount: 0,
});

export const chargeKernelJsonSnapshotValues = (
    state: KernelJsonSnapshotState,
    additionalValueCount: number,
): void => {
    if (
        additionalValueCount >
        maximumKernelJsonSnapshotValueCount - state.valueCount
    ) {
        throw new RangeError(
            'The kernel JSON input exceeds the accepted value count.',
        );
    }
    state.valueCount += additionalValueCount;
};

const chargeKernelJsonSnapshotString = (
    state: KernelJsonSnapshotState,
    value: string,
): void => {
    if (
        value.length >
        maximumKernelJsonSnapshotStringCodeUnitCount - state.stringCodeUnitCount
    ) {
        throw new RangeError(
            'The kernel JSON input exceeds the accepted string size.',
        );
    }
    state.stringCodeUnitCount += value.length;
};

const assertNoCustomJsonSerialization = (
    descriptors: PropertyDescriptorMap,
    valuePath: string,
): void => {
    const toJsonDescriptor = descriptors.toJSON;
    if (
        toJsonDescriptor !== undefined &&
        ('get' in toJsonDescriptor ||
            'set' in toJsonDescriptor ||
            ('value' in toJsonDescriptor &&
                typeof toJsonDescriptor.value === 'function'))
    ) {
        throw new TypeError(
            `${valuePath} cannot contain custom JSON serialization.`,
        );
    }
};

const boundedOwnPropertyDescriptors = (
    value: object,
    valuePath: string,
): PropertyDescriptorMap => {
    const propertyKeys = Reflect.ownKeys(value);
    if (propertyKeys.length > maximumKernelJsonSnapshotValueCount) {
        throw new RangeError(
            `${valuePath} exceeds the accepted own-property count.`,
        );
    }
    const descriptors = Object.create(null) as PropertyDescriptorMap;
    for (const propertyKey of propertyKeys) {
        const descriptor = Object.getOwnPropertyDescriptor(value, propertyKey);
        if (descriptor !== undefined) {
            Object.defineProperty(descriptors, propertyKey, {
                configurable: true,
                enumerable: true,
                value: descriptor,
                writable: true,
            });
        }
    }

    return descriptors;
};

const ordinaryArrayDescriptorsInternal = (
    value: unknown,
    valuePath: string,
): Readonly<{
    readonly descriptors: PropertyDescriptorMap;
    readonly length: number;
}> => {
    if (!Array.isArray(value)) {
        throw new TypeError(`${valuePath} must be an array.`);
    }
    const prototype = Reflect.getPrototypeOf(value);
    if (prototype !== Array.prototype && prototype !== null) {
        throw new TypeError(`${valuePath} must be an ordinary array.`);
    }
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    if (
        lengthDescriptor === undefined ||
        !('value' in lengthDescriptor) ||
        !Number.isSafeInteger(lengthDescriptor.value) ||
        lengthDescriptor.value < 0
    ) {
        throw new TypeError(`${valuePath} has an invalid array length.`);
    }
    const arrayLength = lengthDescriptor.value as number;
    if (arrayLength > maximumKernelJsonSnapshotValueCount) {
        throw new RangeError(`${valuePath} exceeds the accepted array length.`);
    }

    return {
        descriptors: boundedOwnPropertyDescriptors(value, valuePath),
        length: arrayLength,
    };
};

const snapshotKernelJsonValueInternal = (
    value: unknown,
    valuePath: string,
    containerDepth: number,
    arrayElement: boolean,
    state: KernelJsonSnapshotState,
): unknown => {
    chargeKernelJsonSnapshotValues(state, 1);
    if (value === null) {
        return null;
    }

    switch (typeof value) {
        case 'string':
            chargeKernelJsonSnapshotString(state, value);
            return value;
        case 'boolean':
            return value;
        case 'number':
            if (
                !Number.isFinite(value) ||
                (Number.isInteger(value) && !Number.isSafeInteger(value))
            ) {
                throw new TypeError(
                    `${valuePath} must contain only finite interoperable numbers.`,
                );
            }
            return value;
        case 'undefined':
        case 'function':
        case 'symbol':
            return arrayElement ? null : omittedKernelJsonObjectProperty;
        case 'bigint':
            throw new TypeError(`${valuePath} cannot contain a bigint.`);
        case 'object':
            break;
    }

    if (containerDepth >= maximumKernelJsonSnapshotContainerDepth) {
        throw new RangeError(
            `${valuePath} exceeds the accepted JSON nesting depth.`,
        );
    }
    const container = value;
    if (state.activeContainers.has(container)) {
        throw new TypeError(`${valuePath} cannot contain a cyclic value.`);
    }
    state.activeContainers.add(container);
    try {
        const prototype = Reflect.getPrototypeOf(container);
        if (Array.isArray(container)) {
            const { descriptors, length: arrayLength } =
                ordinaryArrayDescriptorsInternal(container, valuePath);
            assertNoCustomJsonSerialization(descriptors, valuePath);
            chargeKernelJsonSnapshotValues(state, arrayLength);
            const snapshot = new Array<unknown>(arrayLength);
            if (prototype === null) {
                Reflect.setPrototypeOf(snapshot, null);
            }
            for (let index = 0; index < arrayLength; index += 1) {
                const descriptor = descriptors[String(index)];
                if (descriptor === undefined) {
                    continue;
                }
                if ('get' in descriptor || 'set' in descriptor) {
                    throw new TypeError(
                        `${valuePath}.${String(index)} cannot be an accessor property.`,
                    );
                }
                const elementSnapshot = snapshotKernelJsonValueInternal(
                    descriptor.value,
                    `${valuePath}.${String(index)}`,
                    containerDepth + 1,
                    true,
                    state,
                );
                snapshot[index] =
                    elementSnapshot === omittedKernelJsonObjectProperty
                        ? null
                        : elementSnapshot;
            }
            return snapshot;
        }

        if (prototype !== Object.prototype && prototype !== null) {
            throw new TypeError(
                `${valuePath} must contain only plain objects and arrays.`,
            );
        }
        const descriptors = boundedOwnPropertyDescriptors(container, valuePath);
        assertNoCustomJsonSerialization(descriptors, valuePath);
        const snapshot = Object.create(prototype) as Record<string, unknown>;
        for (const propertyKey of Reflect.ownKeys(descriptors)) {
            if (typeof propertyKey !== 'string') {
                continue;
            }
            const descriptor = descriptors[propertyKey];
            if (descriptor?.enumerable !== true) {
                continue;
            }
            if ('get' in descriptor || 'set' in descriptor) {
                throw new TypeError(
                    `${valuePath}.${propertyKey} cannot be an accessor property.`,
                );
            }
            chargeKernelJsonSnapshotString(state, propertyKey);
            const propertySnapshot = snapshotKernelJsonValueInternal(
                descriptor.value,
                `${valuePath}.${propertyKey}`,
                containerDepth + 1,
                false,
                state,
            );
            if (propertySnapshot === omittedKernelJsonObjectProperty) {
                continue;
            }
            Object.defineProperty(snapshot, propertyKey, {
                configurable: true,
                enumerable: true,
                value: propertySnapshot,
                writable: true,
            });
        }
        return snapshot;
    } finally {
        state.activeContainers.delete(container);
    }
};

export const snapshotKernelJsonValue = (
    value: unknown,
    valuePath: string,
    state: KernelJsonSnapshotState,
): unknown => {
    const snapshot = snapshotKernelJsonValueInternal(
        value,
        valuePath,
        0,
        false,
        state,
    );

    return snapshot === omittedKernelJsonObjectProperty ? undefined : snapshot;
};

export const plainRecordDescriptors = (
    value: unknown,
    valuePath: string,
): PropertyDescriptorMap => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${valuePath} must be a plain object.`);
    }
    const prototype = Reflect.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError(`${valuePath} must be a plain object.`);
    }

    return boundedOwnPropertyDescriptors(value, valuePath);
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
    return ordinaryArrayDescriptorsInternal(value, valuePath);
};
