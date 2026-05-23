import {
    protocolDigestNamespaceByHashAlias,
    protocolDigestNamespaceValues,
    protocolHashAliasByDigestNamespace,
    protocolHashSemanticNameValues,
} from '@sealed-lattice/types';
import type {
    ProtocolDigest,
    ProtocolDigestNamespace,
    ProtocolHash,
    ProtocolHashSemanticName,
} from '@sealed-lattice/types';

import { canonicalJson, hash512Hex } from './canonical-json.js';

export {
    protocolDigestNamespaceByHashAlias,
    protocolDigestNamespaceValues,
    protocolHashAliasByDigestNamespace,
    protocolHashSemanticNameValues,
};
export type { ProtocolDigestNamespace, ProtocolHashSemanticName };

const textEncoder = new TextEncoder();

const protocolDigestNamespaceSet = new Set<string>(
    protocolDigestNamespaceValues,
);

const pascalCaseToKebabCase = (value: string): string =>
    value
        .replace(/([A-Z]+)([A-Z][a-z])/gu, '$1-$2')
        .replace(/([a-z0-9])([A-Z])/gu, '$1-$2')
        .toLowerCase();

const reservedProtocolDigestDomainSet = new Set(
    protocolDigestNamespaceValues.map(
        (reservedNamespace) =>
            `sealed-lattice-root/${pascalCaseToKebabCase(reservedNamespace)}-v1`,
    ),
);

export const resolveProtocolDigestDomain = (namespace: string): string => {
    if (protocolDigestNamespaceSet.has(namespace)) {
        return `sealed-lattice-root/${pascalCaseToKebabCase(namespace)}-v1`;
    }

    if (namespace.startsWith('sealed-lattice-root/')) {
        if (reservedProtocolDigestDomainSet.has(namespace)) {
            return namespace;
        }

        throw new TypeError(
            'Protocol digest namespace domain must be reserved in the transcript-core registry.',
        );
    }
    if (!/^[A-Z][A-Za-z0-9]*$/u.test(namespace)) {
        throw new TypeError(
            'Protocol digest namespace must be a reserved PascalCase name.',
        );
    }

    throw new TypeError(
        'Protocol digest namespace must be reserved in the transcript-core registry.',
    );
};

export const deriveProtocolDigest = (
    namespace: string,
    value: unknown,
): ProtocolDigest =>
    hash512Hex(resolveProtocolDigestDomain(namespace), [
        textEncoder.encode(canonicalJson(value)),
    ]);

export const resolveProtocolHashNamespace = (
    semanticName: ProtocolHashSemanticName,
): ProtocolDigestNamespace => protocolDigestNamespaceByHashAlias[semanticName];

export const deriveProtocolHash = (
    semanticName: ProtocolHashSemanticName,
    value: unknown,
): ProtocolHash =>
    deriveProtocolDigest(resolveProtocolHashNamespace(semanticName), value);

export const derivePolicyDigest = (
    namespace: ProtocolDigestNamespace,
    policy: unknown,
): ProtocolDigest => deriveProtocolDigest(namespace, policy);
