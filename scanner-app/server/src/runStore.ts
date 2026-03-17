import fs from 'node:fs/promises';
import path from 'node:path';

import { resultsRoot } from './config.js';

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

async function listFiles(runPath: string, runId: string): Promise<RunFile[]> {
  const entries = await fs.readdir(runPath, { withFileTypes: true });
  const files = await Promise.all(
    entries
      .filter((entry) => entry.isFile())
      .map(async (entry) => {
        const absolutePath = path.join(runPath, entry.name);
        const stats = await fs.stat(absolutePath);
        return {
          name: entry.name,
          url: `/results/${encodeURIComponent(runId)}/${encodeURIComponent(entry.name)}`,
          size: stats.size,
          modifiedAt: stats.mtime.toISOString(),
        } satisfies RunFile;
      }),
  );

  return files.sort((left, right) => right.modifiedAt.localeCompare(left.modifiedAt));
}

export async function listRuns(): Promise<RunItem[]> {
  try {
    const entries = await fs.readdir(resultsRoot, { withFileTypes: true });
    const runs = await Promise.all(
      entries
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
          } satisfies RunItem;
        }),
    );

    return runs.sort((left, right) => right.modifiedAt.localeCompare(left.modifiedAt));
  } catch {
    return [];
  }
}

export async function getRun(runId: string): Promise<RunItem | null> {
  const runs = await listRuns();
  return runs.find((run) => run.id === runId) ?? null;
}
