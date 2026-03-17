import { spawn } from 'node:child_process';

import { bridgeScriptPath, projectRoot, pythonExecutable } from './config.js';

export async function runScanAction(action: string, payload: Record<string, unknown>) {
  return new Promise<Record<string, unknown>>((resolve, reject) => {
    const child = spawn(pythonExecutable, [bridgeScriptPath, '--action', action], {
      cwd: projectRoot,
      env: process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', (error) => {
      reject(new Error(`Kon Python bridge niet starten: ${error.message}`));
    });

    child.on('close', (code) => {
      const output = stdout.trim();
      const lastLine = output.split(/\r?\n/).filter(Boolean).at(-1) ?? '';
      const rawJson = lastLine || output;

      if (!rawJson) {
        reject(new Error(stderr.trim() || 'Lege respons van Python bridge.'));
        return;
      }

      try {
        const parsed = JSON.parse(rawJson) as Record<string, unknown>;
        if (code === 0) {
          resolve(parsed);
          return;
        }

        const errorMessage = typeof parsed.error === 'string'
          ? parsed.error
          : stderr.trim() || 'Scan actie is mislukt.';
        reject(new Error(errorMessage));
      } catch {
        reject(new Error(stderr.trim() || output || `Python bridge faalde met exitcode ${code ?? 'unknown'}.`));
      }
    });

    child.stdin.write(JSON.stringify(payload ?? {}));
    child.stdin.end();
  });
}
