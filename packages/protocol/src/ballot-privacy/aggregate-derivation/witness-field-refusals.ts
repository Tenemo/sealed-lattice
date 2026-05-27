import type { ProtocolDigest, RefusalRecord } from '@sealed-lattice/types';

import {
    createAggregateRefusal,
    forbiddenPublicWitnessFieldNames,
} from './constants.js';

const maximumPublicObjectTraversalDepth = 64;
const maximumPublicObjectTraversalObjects = 10_000;

export const collectForbiddenWitnessFieldRefusals = (
    value: unknown,
    objectDigest: ProtocolDigest | undefined,
    path: string,
    options: {
        readonly publicObjectDescription: string;
    },
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const seenObjects = new WeakSet<object>();
    const pendingValues: {
        readonly depth: number;
        readonly path: string;
        readonly value: unknown;
    }[] = [{ depth: 0, path, value }];
    let visitedObjectCount = 0;

    while (pendingValues.length > 0) {
        const currentValue = pendingValues.pop();
        if (currentValue === undefined) {
            break;
        }
        if (
            typeof currentValue.value !== 'object' ||
            currentValue.value === null
        ) {
            continue;
        }
        if (seenObjects.has(currentValue.value)) {
            refusedObjects.push(
                createAggregateRefusal(
                    `${options.publicObjectDescription} must not contain cyclic object references at ${currentValue.path}.`,
                    objectDigest,
                ),
            );
            continue;
        }
        seenObjects.add(currentValue.value);
        visitedObjectCount += 1;
        if (visitedObjectCount > maximumPublicObjectTraversalObjects) {
            refusedObjects.push(
                createAggregateRefusal(
                    `${options.publicObjectDescription} traversal exceeded the maximum object count.`,
                    objectDigest,
                ),
            );
            break;
        }
        if (currentValue.depth > maximumPublicObjectTraversalDepth) {
            refusedObjects.push(
                createAggregateRefusal(
                    `${options.publicObjectDescription} nesting is too deep at ${currentValue.path}.`,
                    objectDigest,
                ),
            );
            continue;
        }
        if (Array.isArray(currentValue.value)) {
            for (
                let itemIndex = currentValue.value.length - 1;
                itemIndex >= 0;
                itemIndex -= 1
            ) {
                pendingValues.push({
                    depth: currentValue.depth + 1,
                    path: `${currentValue.path}[${itemIndex}]`,
                    value: currentValue.value[itemIndex],
                });
            }
            continue;
        }

        const entries = Object.entries(
            currentValue.value as Record<string, unknown>,
        );
        for (
            let entryIndex = entries.length - 1;
            entryIndex >= 0;
            entryIndex -= 1
        ) {
            const entry = entries[entryIndex];
            if (entry === undefined) {
                continue;
            }
            const [fieldName, fieldValue] = entry;
            const fieldPath = `${currentValue.path}.${fieldName}`;
            if (forbiddenPublicWitnessFieldNames.has(fieldName)) {
                refusedObjects.push(
                    createAggregateRefusal(
                        `${options.publicObjectDescription} must not expose witness field ${fieldPath}.`,
                        objectDigest,
                    ),
                );
                continue;
            }
            pendingValues.push({
                depth: currentValue.depth + 1,
                path: fieldPath,
                value: fieldValue,
            });
        }
    }

    return refusedObjects;
};
