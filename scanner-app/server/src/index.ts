import cors from 'cors';
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';

import { clientDistPath, port, resultsRoot } from './config.js';
import { runScanAction } from './pythonBridge.js';
import { getRunFilePathForUser, getRunForUser, listRunsForUser, reserveRunForUser } from './runStore.js';
import { scanDefinitionMap, scanDefinitions } from './scans.js';

const app = express();
const scanRequestSchema = z.record(z.unknown());

function sanitizeRunSegment(input: string): string {
  const normalized = input.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  return normalized || 'scan';
}

function buildRunId(domainOrLabel: string): string {
  const stamp = new Date().toISOString().replace(/[:T]/g, '-').replace(/\.\d+Z$/, '');
  return `${sanitizeRunSegment(domainOrLabel)}_${stamp}`;
}

function getRequestUserId(request: express.Request): string {
  const header = request.header('x-user-id');
  const userId = typeof header === 'string' ? header.trim() : '';
  if (!userId) {
    throw new Error('Missing user identity (x-user-id header).');
  }
  return userId;
}

app.use(cors());
app.use(express.json({ limit: '5mb' }));

app.get('/api/health', (_request, response) => {
  response.json({ ok: true });
});

app.get('/api/scans', (_request, response) => {
  response.json({ scans: scanDefinitions });
});

app.get('/api/runs', async (request, response) => {
  try {
    const userId = getRequestUserId(request);
    response.json({ runs: await listRunsForUser(userId) });
  } catch (error) {
    response.status(401).json({ ok: false, error: error instanceof Error ? error.message : 'Niet geauthenticeerd.' });
  }
});

app.get('/api/runs/:runId', async (request, response) => {
  try {
    const userId = getRequestUserId(request);
    const run = await getRunForUser(request.params.runId, userId);
    if (!run) {
      response.status(404).json({ ok: false, error: 'Run niet gevonden.' });
      return;
    }

    response.json({ ok: true, run });
  } catch (error) {
    response.status(401).json({ ok: false, error: error instanceof Error ? error.message : 'Niet geauthenticeerd.' });
  }
});

app.get('/api/runs/:runId/files/:fileName', async (request, response) => {
  try {
    const userId = getRequestUserId(request);
    const filePath = await getRunFilePathForUser(request.params.runId, request.params.fileName, userId);
    if (!filePath) {
      response.status(404).json({ ok: false, error: 'Bestand niet gevonden.' });
      return;
    }

    response.sendFile(path.resolve(filePath));
  } catch (error) {
    response.status(401).json({ ok: false, error: error instanceof Error ? error.message : 'Niet geauthenticeerd.' });
  }
});

app.post('/api/scans/:scanId', async (request, response) => {
  const scanId = request.params.scanId;
  if (!scanDefinitionMap.has(scanId)) {
    response.status(404).json({ ok: false, error: 'Onbekende scan actie.' });
    return;
  }

  const parsedBody = scanRequestSchema.safeParse(request.body ?? {});
  if (!parsedBody.success) {
    response.status(400).json({ ok: false, error: 'Ongeldige request body.' });
    return;
  }

  const payload = parsedBody.data;
  let userId: string;
  try {
    userId = getRequestUserId(request);
  } catch (error) {
    response.status(401).json({ ok: false, error: error instanceof Error ? error.message : 'Niet geauthenticeerd.' });
    return;
  }

  const payloadRunId = typeof payload.runId === 'string' && payload.runId.trim() ? payload.runId.trim() : '';
  const inferredDomain = typeof payload.domain === 'string' && payload.domain.trim()
    ? payload.domain
    : (typeof payload.term === 'string' && payload.term.trim() ? payload.term : 'manual_scan');

  const runId = payloadRunId || buildRunId(inferredDomain);

  try {
    await reserveRunForUser(runId, userId);
  } catch (error) {
    response.status(403).json({ ok: false, error: error instanceof Error ? error.message : 'Geen toegang tot deze run.' });
    return;
  }

  const scopedPayload = {
    ...payload,
    runId,
  };

  // Full-scan can exceed ingress HTTP timeouts, so run it async and return immediately.
  if (scanId === 'full-scan') {
    void runScanAction(scanId, scopedPayload).catch((error) => {
      console.error(`[full-scan:${runId}] scan actie mislukt`, error);
    });

    response.status(202).json({
      ok: true,
      queued: true,
      action: scanId,
      runId,
      message: 'Volledige scan is gestart. Vernieuw de runs-lijst om voortgang te zien.',
    });
    return;
  }

  try {
    const result = await runScanAction(scanId, scopedPayload);
    response.json(result);
  } catch (error) {
    response.status(500).json({
      ok: false,
      error: error instanceof Error ? error.message : 'Onbekende fout tijdens uitvoeren van de scan.',
    });
  }
});

if (fs.existsSync(clientDistPath)) {
  app.use(express.static(clientDistPath));
  app.get('*', (request, response, next) => {
    if (request.path.startsWith('/api/') || request.path.startsWith('/results/')) {
      next();
      return;
    }

    response.sendFile(path.join(clientDistPath, 'index.html'));
  });
} else {
  app.get('/', (_request, response) => {
    response.json({
      ok: true,
      message: 'API server draait. Start de React client via npm run dev --workspace client.',
    });
  });
}

app.listen(port, () => {
  console.log(`Scanner API draait op http://localhost:${port}`);
});
