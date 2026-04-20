import { promises as fs } from 'node:fs';
import path from 'node:path';

import {
    apiNavigationPath,
    apiReferenceRoot,
    publicApiReferenceEntries,
} from './public-api-reference';

const repoRoot = process.cwd();
const referenceRoot = path.resolve(repoRoot, apiReferenceRoot);
const navigationPath = path.resolve(repoRoot, apiNavigationPath);

type NavigationItem = {
    children?: NavigationItem[];
    path?: string;
    title?: string;
};

const moduleOrder = new Map(
    publicApiReferenceEntries.map((entry, index) => [
        entry.moduleName,
        index + 1,
    ]),
);

const internalLinkPattern = /(!?\[[^\]]*])\(([^)#\s]+)(#[^)]+)?\)/g;
const generatedPreamblePattern = /^[\s\S]*?(?:^|\r?\n)# .+\r?\n\r?\n/;
const sentenceCaseReplacements: readonly (readonly [RegExp, string])[] = [
    [/\bType Aliases\b/g, 'Type aliases'],
    [/\bType Alias\b/g, 'Type alias'],
    [/\bType Declarations\b/g, 'Type declarations'],
    [/\bType Declaration\b/g, 'Type declaration'],
    [/\bType Parameters\b/g, 'Type parameters'],
    [/\bType Parameter\b/g, 'Type parameter'],
    [/\bCall Signatures\b/g, 'Call signatures'],
    [/\bCall Signature\b/g, 'Call signature'],
    [/\bIndex Signatures\b/g, 'Index signatures'],
    [/\bIndex Signature\b/g, 'Index signature'],
    [/\bDefault Value\b/g, 'Default value'],
    [/\bDefined In:(?=\s|$)/g, 'Defined in:'],
    [/\bImplementation Of\b/g, 'Implementation of'],
    [/\bImplemented By\b/g, 'Implemented by'],
    [/\bInherited From\b/g, 'Inherited from'],
    [/\bExtended By\b/g, 'Extended by'],
] as const;

const toReferenceConfigRelativePath = (configPath: string): string =>
    path.relative(apiReferenceRoot, configPath).replace(/\\/g, '/');

const toReferenceRelativePath = (absolutePath: string): string =>
    path.relative(referenceRoot, absolutePath).replace(/\\/g, '/');

const moduleNameByReferencePath = new Map(
    publicApiReferenceEntries.map((entry) => [
        toReferenceConfigRelativePath(entry.apiReferencePagePath),
        entry.moduleName,
    ]),
);

const toRoutePath = (absolutePath: string): string => {
    const relativePath = toReferenceRelativePath(absolutePath);
    const extension = path.extname(relativePath);
    const fileName = path.basename(relativePath, extension);
    const directorySegments = path
        .dirname(relativePath)
        .split(path.sep)
        .join('/')
        .split('/')
        .filter(Boolean)
        .map((segment) => segment.toLowerCase());
    const routeSegments =
        fileName === 'index'
            ? directorySegments
            : [...directorySegments, fileName.toLowerCase()];

    return routeSegments.length === 0 ? '/' : `/${routeSegments.join('/')}/`;
};

const toRelativeRouteTarget = (fromFile: string, rawTarget: string): string => {
    const absoluteTarget = path.resolve(path.dirname(fromFile), rawTarget);
    const fromRoute = toRoutePath(fromFile);
    const targetRoute = toRoutePath(absoluteTarget);
    const fromSegments = fromRoute.slice(1, -1);
    const targetSegments = targetRoute.slice(1, -1);
    const relativeTarget = path.posix.relative(fromSegments, targetSegments);

    return relativeTarget === '' ? './' : `${relativeTarget}/`;
};

const collectMarkdownFiles = async (directory: string): Promise<string[]> => {
    const files: string[] = [];
    const pending = [directory];

    while (pending.length > 0) {
        const current = pending.pop();
        if (current === undefined) {
            continue;
        }

        const entries = await fs.readdir(current, { withFileTypes: true });
        for (const entry of entries) {
            const entryPath = path.join(current, entry.name);
            if (entry.isDirectory()) {
                pending.push(entryPath);
            } else if (entry.isFile() && entryPath.endsWith('.md')) {
                files.push(entryPath);
            }
        }
    }

    return files.sort();
};

const deriveTitleFromRelativePath = (relativePath: string): string => {
    if (relativePath === 'index.md') {
        return 'Generated reference';
    }

    const moduleName = moduleNameByReferencePath.get(relativePath);
    if (moduleName !== undefined) {
        const segments = moduleName.split('/');
        return segments[segments.length - 1];
    }

    return path.basename(relativePath, '.md');
};

const deriveSidebarOrder = (relativePath: string): number | undefined => {
    const moduleName = moduleNameByReferencePath.get(relativePath);
    if (moduleName === undefined) {
        return undefined;
    }

    return moduleOrder.get(moduleName);
};

const rewriteMarkdownLinks = (content: string, fromFile: string): string =>
    content.replace(
        internalLinkPattern,
        (fullMatch, label, rawTarget: string, hash = ''): string => {
            if (
                rawTarget.startsWith('#') ||
                rawTarget.startsWith('http://') ||
                rawTarget.startsWith('https://') ||
                rawTarget.startsWith('mailto:') ||
                !rawTarget.endsWith('.md')
            ) {
                return fullMatch;
            }

            const rewrittenTarget = toRelativeRouteTarget(fromFile, rawTarget);

            return `${label}(${rewrittenTarget}${hash})`;
        },
    );

const rewriteSentenceCase = (content: string): string => {
    let rewritten = content;

    for (const [pattern, replacement] of sentenceCaseReplacements) {
        rewritten = rewritten.replace(pattern, replacement);
    }

    return rewritten;
};

const normalizeNavigationTitles = (
    items: readonly NavigationItem[],
): NavigationItem[] =>
    items.map((item) => ({
        ...item,
        ...(typeof item.title === 'string'
            ? {
                  title: rewriteSentenceCase(item.title),
              }
            : {}),
        ...(Array.isArray(item.children)
            ? {
                  children: normalizeNavigationTitles(item.children),
              }
            : {}),
    }));

const main = async (): Promise<void> => {
    await fs.rm(path.join(referenceRoot, 'modules.md'), { force: true });

    const navigation = normalizeNavigationTitles(
        JSON.parse(
            await fs.readFile(navigationPath, 'utf8'),
        ) as NavigationItem[],
    );
    const titleByPath = new Map<string, string>();

    await fs.writeFile(
        navigationPath,
        `${JSON.stringify(navigation, null, 2)}\n`,
    );

    const visitNavigation = (items: readonly NavigationItem[]): void => {
        for (const item of items) {
            if (
                typeof item.path === 'string' &&
                typeof item.title === 'string'
            ) {
                titleByPath.set(item.path, item.title);
            }

            if (Array.isArray(item.children)) {
                visitNavigation(item.children);
            }
        }
    };

    visitNavigation(navigation);

    const markdownFiles = await collectMarkdownFiles(referenceRoot);

    for (const file of markdownFiles) {
        const relativePath = toReferenceRelativePath(file);
        const title =
            titleByPath.get(relativePath) ??
            deriveTitleFromRelativePath(relativePath);
        const order = deriveSidebarOrder(relativePath);
        const isGeneratedRoot = relativePath === 'index.md';
        const moduleName = moduleNameByReferencePath.get(relativePath);
        const generatedModuleSummary =
            moduleName !== undefined
                ? `Generated reference page for the \`${moduleName}\` public API surface.`
                : undefined;

        let content = await fs.readFile(file, 'utf8');
        content = content.replace(generatedPreamblePattern, '');
        content = rewriteMarkdownLinks(content, file);
        content = rewriteSentenceCase(content);

        const frontmatterLines = [
            '---',
            `title: ${JSON.stringify(title)}`,
            isGeneratedRoot
                ? 'description: "Export-driven symbol reference for the public API."'
                : generatedModuleSummary !== undefined
                  ? `description: ${JSON.stringify(generatedModuleSummary)}`
                  : null,
            'editUrl: false',
            isGeneratedRoot
                ? 'sidebar:\n  hidden: true'
                : order !== undefined
                  ? `sidebar:\n  order: ${order}`
                  : null,
            '---',
            '',
        ].filter((line): line is string => line !== null);

        await fs.writeFile(file, `${frontmatterLines.join('\n')}${content}`);
    }
};

void main();
