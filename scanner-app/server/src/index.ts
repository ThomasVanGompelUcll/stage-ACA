import cors from 'cors';
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';

import { clientDistPath, port, resultsRoot } from './config.js';
import { runScanAction } from './pythonBridge.js';
import { getRun, listRuns } from './runStore.js';
import { scanDefinitionMap, scanDefinitions } from './scans.js';

const app = express();
const scanRequestSchema = z.record(z.unknown());

app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use('/results', express.static(resultsRoot));

app.get('/api/health', (_request, response) => {
  response.json({ ok: true });
});

app.get('/api/scans', (_request, response) => {
  response.json({ scans: scanDefinitions });
});

app.get('/api/runs', async (_request, response) => {
  response.json({ runs: await listRuns() });
});

app.get('/api/runs/:runId', async (request, response) => {
  const run = await getRun(request.params.runId);
  if (!run) {
    response.status(404).json({ ok: false, error: 'Run niet gevonden.' });
    return;
  }

  response.json({ ok: true, run });
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

  try {
    const result = await runScanAction(scanId, parsedBody.data);
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
