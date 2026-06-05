import { protocolHashNamespaceValues } from '@sealed-lattice/types';
import type {
    ProtocolHash,
    ProtocolHashNamespace,
} from '@sealed-lattice/types';

import { canonicalJson, hash512Hex } from './canonical-json.js';

export { protocolHashNamespaceValues };
export type { ProtocolHashNamespace };

const textEncoder = new TextEncoder();

const protocolHashNamespaceSet = new Set<string>(protocolHashNamespaceValues);

// PascalCase namespace -> kebab-case, feeding the `sealed-lattice-root/<kebab>-v1`
// wire domain template below. This derivation is the domain-separation namespace
// for every deriveProtocolHash and must stay stable: any change rotates all hashes.
const pascalCaseToKebabCase = (value: string): string =>
    value
        .replace(/([A-Z]+)([A-Z][a-z])/gu, '$1-$2')
        .replace(/([a-z0-9])([A-Z])/gu, '$1-$2')
        .toLowerCase();

const reservedProtocolHashDomainSet = new Set(
    protocolHashNamespaceValues.map(
        (reservedNamespace) =>
            `sealed-lattice-root/${pascalCaseToKebabCase(reservedNamespace)}-v1`,
    ),
);

// Fails closed: only namespaces pre-registered in the transcript-core registry
// (protocolHashNamespaceValues) resolve to a domain. Unknown PascalCase names,
// or unreserved `sealed-lattice-root/...` strings, throw — no unscoped domains.
export const resolveProtocolHashDomain = (namespace: string): string => {
    if (protocolHashNamespaceSet.has(namespace)) {
        return `sealed-lattice-root/${pascalCaseToKebabCase(namespace)}-v1`;
    }

    if (namespace.startsWith('sealed-lattice-root/')) {
        if (reservedProtocolHashDomainSet.has(namespace)) {
            return namespace;
        }

        throw new TypeError(
            'Protocol hash namespace domain must be reserved in the transcript-core registry.',
        );
    }
    if (!/^[A-Z][A-Za-z0-9]*$/u.test(namespace)) {
        throw new TypeError(
            'Protocol hash namespace must be a reserved PascalCase name.',
        );
    }

    throw new TypeError(
        'Protocol hash namespace must be reserved in the transcript-core registry.',
    );
};

export const deriveProtocolHash = (
    namespace: string,
    value: unknown,
): ProtocolHash =>
    hash512Hex(resolveProtocolHashDomain(namespace), [
        textEncoder.encode(canonicalJson(value)),
    ]);
