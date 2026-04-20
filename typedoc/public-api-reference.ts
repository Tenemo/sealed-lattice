type PublicApiReferenceEntry = {
    apiReferencePagePath: string;
    entryPoint: string;
    moduleName: string;
};

const rootModuleName = 'sealed-lattice';

export const docsContentRoot = 'docs/src/content/docs';
const apiSectionRoot = `${docsContentRoot}/api`;
export const apiReferenceRoot = `${apiSectionRoot}/reference`;
export const apiNavigationPath = `${apiReferenceRoot}/navigation.json`;

export const publicApiReferenceEntries: readonly PublicApiReferenceEntry[] = [
    {
        moduleName: rootModuleName,
        entryPoint: `typedoc/entry-points/${rootModuleName}.ts`,
        apiReferencePagePath: `${apiReferenceRoot}/${rootModuleName}.md`,
    },
];

export const typeDocEntryPoints = publicApiReferenceEntries.map(
    (entry): string => entry.entryPoint,
);
