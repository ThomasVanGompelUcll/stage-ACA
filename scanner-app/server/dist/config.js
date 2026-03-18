import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const serverRoot = path.resolve(__dirname, '..');
export const appRoot = path.resolve(serverRoot, '..');
export const projectRoot = path.resolve(appRoot, '..');
export const resultsRoot = path.join(projectRoot, 'results');
export const bridgeScriptPath = path.join(projectRoot, 'scan_bridge.py');
export const clientDistPath = path.join(appRoot, 'client', 'dist');
const venvPython = process.platform === 'win32'
    ? path.join(projectRoot, '.venv', 'Scripts', 'python.exe')
    : path.join(projectRoot, '.venv', 'bin', 'python');
export const pythonExecutable = process.env.PYTHON_EXECUTABLE
    || (fs.existsSync(venvPython) ? venvPython : 'python');
export const port = Number(process.env.PORT || 4000);
