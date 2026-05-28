// Shared parsing for runtime snippet variables.
// Syntax: {{variable_name}}

const SNIPPET_VAR_RE = /\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}/g;

export function normalizeSnippetVarName(name) {
    return String(name ?? '')
        .trim()
        .replace(/\s+/g, '_')
        .replace(/[^a-zA-Z0-9_]/g, '')
        .replace(/^[^a-zA-Z_]+/, '');
}

export function formatSnippetVar(name) {
    const normalized = normalizeSnippetVarName(name);
    return normalized ? `{{${normalized}}}` : '';
}

export function extractSnippetVars(command) {
    const out = [];
    const seen = new Set();
    let match;

    SNIPPET_VAR_RE.lastIndex = 0;
    while ((match = SNIPPET_VAR_RE.exec(command ?? '')) !== null) {
        const name = match[1];
        if (!seen.has(name)) {
            seen.add(name);
            out.push(name);
        }
    }

    return out;
}

export function replaceSnippetVars(command, values) {
    SNIPPET_VAR_RE.lastIndex = 0;
    return String(command ?? '').replace(SNIPPET_VAR_RE, (_, name) => values[name] ?? '');
}
