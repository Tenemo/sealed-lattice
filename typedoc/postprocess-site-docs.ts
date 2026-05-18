import { promises as fs } from 'node:fs';
import path from 'node:path';

import { collectFiles } from '../tools/internal/files.js';

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

const toPosixPath = (value: string): string => value.replace(/\\/g, '/');

const toReferenceConfigRelativePath = (configPath: string): string =>
    toPosixPath(path.relative(apiReferenceRoot, configPath));

const toReferenceRelativePath = (absolutePath: string): string =>
    toPosixPath(path.relative(referenceRoot, absolutePath));

const moduleNameByReferencePath = new Map(
    publicApiReferenceEntries.map((entry) => [
        toReferenceConfigRelativePath(entry.apiReferencePagePath),
        entry.moduleName,
    ]),
);

const toReferenceRoutePath = (relativePath: string): string => {
    const normalizedPath = path.posix.normalize(relativePath);

    if (normalizedPath === 'index.md') {
        return '';
    }

    if (normalizedPath.endsWith('/index.md')) {
        return normalizedPath.slice(0, -'index.md'.length);
    }

    return `${normalizedPath.slice(0, -'.md'.length)}/`;
};

const collectMarkdownFiles = async (directory: string): Promise<string[]> =>
    collectFiles(directory, { extensions: ['.md'] });

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

const rewriteMarkdownLinks = (
    content: string,
    sourceRelativePath: string,
): string =>
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

            const sourceDirectory = path.posix.dirname(sourceRelativePath);
            const resolvedTargetPath = path.posix.normalize(
                rawTarget.startsWith('/')
                    ? rawTarget.slice(1)
                    : path.posix.join(sourceDirectory, rawTarget),
            );
            const sourceRoutePath = toReferenceRoutePath(sourceRelativePath);
            const targetRoutePath = toReferenceRoutePath(resolvedTargetPath);
            const rewrittenTargetBase = path.posix.relative(
                sourceRoutePath === '' ? '.' : sourceRoutePath,
                targetRoutePath === '' ? '.' : targetRoutePath,
            );
            const rewrittenTarget = `${
                rewrittenTargetBase === '' ? '.' : rewrittenTargetBase
            }/`;

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

const isStructuralMarkdownLine = (line: string): boolean =>
    /^\s*$/.test(line) ||
    /^\s{0,3}(#{1,6}\s|(```|~~~))/.test(line) ||
    /^\s{0,3}([-*_])([\t ]*\1){2,}\s*$/.test(line) ||
    /^\s*\|/.test(line) ||
    /^\s*:?-{3,}:?(\s*\|\s*:?-{3,}:?)+\s*$/.test(line) ||
    /^\s*([-+*]|\d+[.)])\s+/.test(line) ||
    /^\s*\[[^\]]+]:\s+/.test(line) ||
    /^\s*(:::+|---\s*$)/.test(line) ||
    /^\s*(import\s|export\s)/.test(line) ||
    /^\s*(<!--|-->|<\/?[A-Za-z][^>]*>?|{\/?[A-Za-z])/.test(line) ||
    /^\s{4,}\S/.test(line);

const isPlainQuoteLine = (line: string): boolean => {
    const match = /^>\s*(.+)$/.exec(line);
    if (match === null) {
        return false;
    }

    const content = match[1];

    return !/^\s{0,3}(#{1,6}\s|(```|~~~)|([-+*]|\d+[.)])\s+|\|)/.test(content);
};

const unwrapMarkdownProse = (content: string): string => {
    const normalizedContent = content.replace(/\r\n/g, '\n');
    const hasFinalLineEnding = normalizedContent.endsWith('\n');
    const lines =
        hasFinalLineEnding && normalizedContent.length > 0
            ? normalizedContent.slice(0, -1).split('\n')
            : normalizedContent.split('\n');
    const outputLines: string[] = [];
    const paragraphLines: string[] = [];
    const quoteParagraphLines: string[] = [];
    let inCodeFence = false;
    let previousLineCanAcceptListContinuation = false;

    const flushParagraph = (): void => {
        if (paragraphLines.length === 0) {
            return;
        }

        outputLines.push(
            paragraphLines
                .map((line) => line.trim())
                .join(' ')
                .replace(/\s+/g, ' '),
        );
        paragraphLines.length = 0;
    };

    const flushQuoteParagraph = (): void => {
        if (quoteParagraphLines.length === 0) {
            return;
        }

        outputLines.push(
            `> ${quoteParagraphLines
                .map((line) => line.trim())
                .join(' ')
                .replace(/\s+/g, ' ')}`,
        );
        quoteParagraphLines.length = 0;
    };

    for (const line of lines) {
        if (/^\s{0,3}(```|~~~)/.test(line)) {
            flushParagraph();
            flushQuoteParagraph();
            outputLines.push(line);
            inCodeFence = !inCodeFence;
            previousLineCanAcceptListContinuation = false;
            continue;
        }

        if (inCodeFence) {
            outputLines.push(line);
            continue;
        }

        if (/^\s*$/.test(line)) {
            flushParagraph();
            flushQuoteParagraph();
            outputLines.push(line);
            previousLineCanAcceptListContinuation = false;
            continue;
        }

        if (isPlainQuoteLine(line)) {
            flushParagraph();
            quoteParagraphLines.push(line.replace(/^>\s?/, '').trim());
            previousLineCanAcceptListContinuation = false;
            continue;
        }

        const listContinuationMatch = /^\s{1,3}(\S.*)$/.exec(line);
        if (
            previousLineCanAcceptListContinuation &&
            listContinuationMatch !== null &&
            !isStructuralMarkdownLine(line)
        ) {
            flushParagraph();
            flushQuoteParagraph();
            outputLines[outputLines.length - 1] = `${
                outputLines[outputLines.length - 1]
            } ${listContinuationMatch[1].trim()}`.replace(/\s+/g, ' ');
            previousLineCanAcceptListContinuation = true;
            continue;
        }

        if (isStructuralMarkdownLine(line)) {
            flushParagraph();
            flushQuoteParagraph();
            outputLines.push(line);
            previousLineCanAcceptListContinuation =
                /^\s*([-+*]|\d+[.)])\s+/.test(line);
            continue;
        }

        flushQuoteParagraph();
        paragraphLines.push(line);
        previousLineCanAcceptListContinuation = false;
    }

    flushParagraph();
    flushQuoteParagraph();

    return `${outputLines.join('\n')}\n`;
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
        content = rewriteMarkdownLinks(content, relativePath);
        content = rewriteSentenceCase(content);
        content = unwrapMarkdownProse(content);

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
