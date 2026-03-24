import fs from 'node:fs/promises';
import path from 'node:path';
import { resultsRoot } from './config.js';
const OWNER_META_FILE = '.owner.json';
async function safeReadJson(filePath) {
    try {
        const raw = await fs.readFile(filePath, 'utf8');
        return JSON.parse(raw);
    }
    catch {
        return null;
    }
}
async function readRunOwnerMeta(runPath) {
    const raw = await safeReadJson(path.join(runPath, OWNER_META_FILE));
    if (!raw) {
        return null;
    }
    const ownerId = typeof raw.ownerId === 'string' ? raw.ownerId.trim() : '';
    const createdAt = typeof raw.createdAt === 'string' ? raw.createdAt : '';
    if (!ownerId) {
        return null;
    }
    return {
        ownerId,
        createdAt,
    };
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
            url: `/api/runs/${encodeURIComponent(runId)}/files/${encodeURIComponent(entry.name)}`,
            size: stats.size,
            modifiedAt: stats.mtime.toISOString(),
        };
    }));
    return files.sort((left, right) => right.modifiedAt.localeCompare(left.modifiedAt));
}
export async function listRunsForUser(ownerId) {
    try {
        const entries = await fs.readdir(resultsRoot, { withFileTypes: true });
        const runs = await Promise.all(entries
            .filter((entry) => entry.isDirectory())
            .map(async (entry) => {
            const runPath = path.join(resultsRoot, entry.name);
            const meta = await readRunOwnerMeta(runPath);
            if (!meta || meta.ownerId !== ownerId) {
                return null;
            }
            const stats = await fs.stat(runPath);
            const summary = await safeReadJson(path.join(runPath, 'summary.json'));
            const files = await listFiles(runPath, entry.name);
            return {
                id: entry.name,
                path: runPath,
                modifiedAt: stats.mtime.toISOString(),
                summary,
                dashboardUrl: files.some((file) => file.name === 'dashboard.html')
                    ? `/api/runs/${encodeURIComponent(entry.name)}/files/dashboard.html`
                    : null,
                files,
            };
        }));
        return runs
            .filter((run) => run !== null)
            .sort((left, right) => right.modifiedAt.localeCompare(left.modifiedAt));
    }
    catch {
        return [];
    }
}
export async function getRunForUser(runId, ownerId) {
    const runs = await listRunsForUser(ownerId);
    return runs.find((run) => run.id === runId) ?? null;
}
export async function reserveRunForUser(runId, ownerId) {
    const runPath = path.join(resultsRoot, runId);
    await fs.mkdir(runPath, { recursive: true });
    const metaPath = path.join(runPath, OWNER_META_FILE);
    const existingMeta = await readRunOwnerMeta(runPath);
    if (existingMeta && existingMeta.ownerId !== ownerId) {
        throw new Error('Je hebt geen toegang tot deze run.');
    }
    if (!existingMeta) {
        const meta = {
            ownerId,
            createdAt: new Date().toISOString(),
        };
        await fs.writeFile(metaPath, JSON.stringify(meta, null, 2), 'utf8');
    }
}
export async function canUserAccessRun(runId, ownerId) {
    const runPath = path.join(resultsRoot, runId);
    try {
        const stats = await fs.stat(runPath);
        if (!stats.isDirectory()) {
            return false;
        }
    }
    catch {
        return false;
    }
    const meta = await readRunOwnerMeta(runPath);
    return !!meta && meta.ownerId === ownerId;
}
export async function getRunFilePathForUser(runId, fileName, ownerId) {
    const allowed = await canUserAccessRun(runId, ownerId);
    if (!allowed) {
        return null;
    }
    const decoded = decodeURIComponent(fileName);
    const safeName = path.basename(decoded);
    if (!safeName || safeName !== decoded) {
        return null;
    }
    const fullPath = path.join(resultsRoot, runId, safeName);
    try {
        const stat = await fs.stat(fullPath);
        if (!stat.isFile()) {
            return null;
        }
        return fullPath;
    }
    catch {
        return null;
    }
}
export async function getRunFilePath(runId, fileName) {
    const runPath = path.join(resultsRoot, runId);
    try {
        const runStats = await fs.stat(runPath);
        if (!runStats.isDirectory()) {
            return null;
        }
    }
    catch {
        return null;
    }
    const decoded = decodeURIComponent(fileName);
    const safeName = path.basename(decoded);
    if (!safeName || safeName !== decoded) {
        return null;
    }
    const fullPath = path.join(runPath, safeName);
    try {
        const stat = await fs.stat(fullPath);
        if (!stat.isFile()) {
            return null;
        }
        return fullPath;
    }
    catch {
        return null;
    }
}
