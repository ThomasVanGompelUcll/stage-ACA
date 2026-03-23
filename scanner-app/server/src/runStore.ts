import fs from 'node:fs/promises';
import path from 'node:path';

import { resultsRoot } from './config.js';

const OWNER_META_FILE = '.owner.json';

export type RunFile = {
  name: string;
  url: string;
  size: number;
  modifiedAt: string;
};

export type RunItem = {
  id: string;
  path: string;
  modifiedAt: string;
  summary: Record<string, unknown> | null;
  dashboardUrl: string | null;
  files: RunFile[];
};

async function safeReadJson(filePath: string): Promise<Record<string, unknown> | null> {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return null;
  }
}

type RunOwnerMeta = {
  ownerId: string;
  createdAt: string;
};

async function readRunOwnerMeta(runPath: string): Promise<RunOwnerMeta | null> {
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

async function listFiles(runPath: string, runId: string, ownerId: string): Promise<RunFile[]> {
  const entries = await fs.readdir(runPath, { withFileTypes: true });
  const files = await Promise.all(
    entries
      .filter((entry) => entry.isFile())
      .map(async (entry) => {
        const absolutePath = path.join(runPath, entry.name);
        const stats = await fs.stat(absolutePath);
        return {
          name: entry.name,
          url: `/api/runs/${encodeURIComponent(runId)}/files/${encodeURIComponent(entry.name)}?userId=${encodeURIComponent(ownerId)}`,
          size: stats.size,
          modifiedAt: stats.mtime.toISOString(),
        } satisfies RunFile;
      }),
  );

  return files.sort((left, right) => right.modifiedAt.localeCompare(left.modifiedAt));
}

export async function listRunsForUser(ownerId: string): Promise<RunItem[]> {
  try {
    const entries = await fs.readdir(resultsRoot, { withFileTypes: true });
    const runs = await Promise.all(
      entries
        .filter((entry) => entry.isDirectory())
        .map(async (entry) => {
          const runPath = path.join(resultsRoot, entry.name);
          const meta = await readRunOwnerMeta(runPath);
          if (!meta || meta.ownerId !== ownerId) {
            return null;
          }

          const stats = await fs.stat(runPath);
          const summary = await safeReadJson(path.join(runPath, 'summary.json'));
          const files = await listFiles(runPath, entry.name, ownerId);
          return {
            id: entry.name,
            path: runPath,
            modifiedAt: stats.mtime.toISOString(),
            summary,
            dashboardUrl: files.some((file) => file.name === 'dashboard.html')
              ? `/api/runs/${encodeURIComponent(entry.name)}/files/dashboard.html?userId=${encodeURIComponent(ownerId)}`
              : null,
            files,
          } satisfies RunItem;
        }),
    );

    return runs
      .filter((run): run is RunItem => run !== null)
      .sort((left, right) => right.modifiedAt.localeCompare(left.modifiedAt));
  } catch {
    return [];
  }
}

export async function getRunForUser(runId: string, ownerId: string): Promise<RunItem | null> {
  const runs = await listRunsForUser(ownerId);
  return runs.find((run) => run.id === runId) ?? null;
}

export async function reserveRunForUser(runId: string, ownerId: string): Promise<void> {
  const runPath = path.join(resultsRoot, runId);
  await fs.mkdir(runPath, { recursive: true });

  const metaPath = path.join(runPath, OWNER_META_FILE);
  const existingMeta = await readRunOwnerMeta(runPath);

  if (existingMeta && existingMeta.ownerId !== ownerId) {
    throw new Error('Je hebt geen toegang tot deze run.');
  }

  if (!existingMeta) {
    const meta: RunOwnerMeta = {
      ownerId,
      createdAt: new Date().toISOString(),
    };
    await fs.writeFile(metaPath, JSON.stringify(meta, null, 2), 'utf8');
  }
}

export async function canUserAccessRun(runId: string, ownerId: string): Promise<boolean> {
  const runPath = path.join(resultsRoot, runId);
  try {
    const stats = await fs.stat(runPath);
    if (!stats.isDirectory()) {
      return false;
    }
  } catch {
    return false;
  }

  const meta = await readRunOwnerMeta(runPath);
  return !!meta && meta.ownerId === ownerId;
}

export async function getRunFilePathForUser(runId: string, fileName: string, ownerId: string): Promise<string | null> {
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
  } catch {
    return null;
  }
}
