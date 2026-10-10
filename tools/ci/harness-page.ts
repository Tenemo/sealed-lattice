// The document around a browser harness page's one inline script.
export const harnessPage = (
    title: string,
    script: string,
    { module = false }: Readonly<{ module?: boolean }> = {},
) =>
    `<!doctype html><html lang="en"><meta charset="utf-8"><title>${title}</title><script${module ? ' type="module"' : ''}>${script}</script>`;

// The content type the harness servers send with a page.
export const harnessPageType = 'text/html; charset=utf-8';
