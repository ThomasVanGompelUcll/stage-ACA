import fs from 'node:fs/promises';
import path from 'node:path';
import { resultsRoot } from './config.js';
async function safeReadJson(filePath) {
    try {
        const raw = await fs.readFile(filePath, 'utf8');
        return JSON.parse(raw);
    }
    catch {
        return null;
    }
}
async function listFiles(runPath, runId) {
    const entries = await fs.readdir(runPath, { withFileTypes: true });
    const files = await Promise.all(entries
        .filter((entry) => entry.isFile())
        .map(async (entry) => {
        const absolutePath = path.join(runPath, entry.name);
        const stats = await fs.stat(absolutePath);
        return {
            name: entry.name,
            url: `/results/${encodeURIComponent(runId)}/${encodeURIComponent(entry.name)}`,
            size: stats.size,
            modifiedAt: stats.mtime.toISOString(),
        };
    }));
    return files.sort((left, right) => right.modifiedAt.localeCompare(left.modifiedAt));
}
export async function listRuns() {
    try {
        const entries = await fs.readdir(resultsRoot, { withFileTypes: true });
        const runs = await Promise.all(entries
            .filter((entry) => entry.isDirectory())
            .map(async (entry) => {
            const runPath = path.join(resultsRoot, entry.name);
            const stats = await fs.stat(runPath);
            const summary = await safeReadJson(path.join(runPath, 'summary.json'));
            const files = await listFiles(runPath, entry.name);
            return {
                id: entry.name,
                path: runPath,
                modifiedAt: stats.mtime.toISOString(),
                summary,
                dashboardUrl: files.some((file) => file.name === 'dashboard.html')
                    ? `/results/${encodeURIComponent(entry.name)}/dashboard.html`
                    : null,
                files,
            };
        }));
        return runs.sort((left, right) => right.modifiedAt.localeCompare(left.modifiedAt));
    }
    catch {
        return [];
    }
}
export async function getRun(runId) {
    const runs = await listRuns();
    return runs.find((run) => run.id === runId) ?? null;
}
