type PublicApiReferenceEntry = {
    apiReferenceIndexPath: string;
    entryPoint: string;
    exportPath: string;
    moduleName: string;
};

const rootModuleName = 'sealed-lattice';

export const docsContentRoot = 'docs/src/content/docs';
const apiSectionRoot = `${docsContentRoot}/api`;
export const apiReferenceRoot = `${apiSectionRoot}/reference`;
export const apiNavigationPath = `${apiReferenceRoot}/navigation.json`;

export const publicApiReferenceEntries: readonly PublicApiReferenceEntry[] = [
    {
        exportPath: '.',
        moduleName: rootModuleName,
        entryPoint: `typedoc/entry-points/${rootModuleName}.ts`,
        apiReferenceIndexPath: `${apiReferenceRoot}/${rootModuleName}/index.md`,
    },
];

export const typeDocEntryPoints = publicApiReferenceEntries.map(
    (entry): string => entry.entryPoint,
);
