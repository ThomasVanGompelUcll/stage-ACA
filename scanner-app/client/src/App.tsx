import { ChangeEvent, FormEvent, useEffect, useMemo, useState } from 'react';

type ScanField = {
  name: string;
  label: string;
  type: 'text' | 'textarea' | 'number' | 'password' | 'run-select' | 'select';
  placeholder?: string;
  required?: boolean;
  description?: string;
  defaultValue?: string | number;
  options?: Array<{
    value: string;
    label: string;
    description?: string;
  }>;
  helpItems?: string[];
};

type ScanDefinition = {
  id: string;
  title: string;
  description: string;
  fields: ScanField[];
};

type RunFile = {
  name: string;
  url: string;
  size: number;
  modifiedAt: string;
};

type RunItem = {
  id: string;
  modifiedAt: string;
  summary: Record<string, unknown> | null;
  dashboardUrl: string | null;
  files: RunFile[];
};

type ScanResponse = Record<string, unknown> & {
  ok?: boolean;
  error?: string;
  runId?: string;
  action?: string;
  term?: string;
  resultCount?: number;
  days?: number;
  previewRows?: Record<string, unknown>[];
};

type FormState = Record<string, string>;

const USER_ID_STORAGE_KEY = 'scanner.userId';

const getUserId = (): string => {
  const existing = window.localStorage.getItem(USER_ID_STORAGE_KEY)?.trim();
  if (existing) {
    return existing;
  }

  const generated = `user-${crypto.randomUUID()}`;
  window.localStorage.setItem(USER_ID_STORAGE_KEY, generated);
  return generated;
};

const fetchJson = async <T,>(url: string, options?: RequestInit): Promise<T> => {
  const userId = getUserId();
  const mergedHeaders = new Headers(options?.headers ?? {});
  mergedHeaders.set('x-user-id', userId);

  const response = await fetch(url, {
    ...options,
    headers: mergedHeaders,
  });
  const raw = await response.text();

  let data: (T & { error?: string }) | null = null;
  try {
    data = JSON.parse(raw) as T & { error?: string };
  } catch {
    const statusPrefix = response.ok ? 'Server respons was geen geldige JSON.' : `Request faalde (${response.status}).`;
    const details = raw.trim().slice(0, 180).replace(/\s+/g, ' ');
    throw new Error(`${statusPrefix} ${details || 'Lege respons.'}`.trim());
  }

  if (!response.ok) {
    throw new Error(data.error || `Request mislukt (${response.status}).`);
  }

  return data;
};

const openProtectedFile = async (url: string, suggestedName?: string): Promise<void> => {
  const userId = getUserId();
  const response = await fetch(url, {
    headers: {
      'x-user-id': userId,
    },
  });

  if (!response.ok) {
    const raw = await response.text();
    const details = raw.trim().slice(0, 180).replace(/\s+/g, ' ');
    throw new Error(details || `Bestand ophalen mislukt (${response.status}).`);
  }

  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const newWindow = window.open(objectUrl, '_blank', 'noopener,noreferrer');

  if (!newWindow) {
    const fallback = document.createElement('a');
    fallback.href = objectUrl;
    fallback.download = suggestedName ?? 'result';
    fallback.rel = 'noopener noreferrer';
    fallback.target = '_blank';
    document.body.appendChild(fallback);
    fallback.click();
    fallback.remove();
  }

  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
};

const buildInitialValues = (scan: ScanDefinition): FormState => Object.fromEntries(
  scan.fields.map((field) => [field.name, field.defaultValue?.toString() ?? '']),
);

const formatBytes = (size: number) => {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
};

const toPrettyJson = (value: unknown) => JSON.stringify(value, null, 2);

function App() {
  const [scans, setScans] = useState<ScanDefinition[]>([]);
  const [runs, setRuns] = useState<RunItem[]>([]);
  const [forms, setForms] = useState<Record<string, FormState>>({});
  const [activeResponse, setActiveResponse] = useState<ScanResponse | null>(null);
  const [isResultModalOpen, setIsResultModalOpen] = useState(false);
  const [pendingPortScanId, setPendingPortScanId] = useState<string | null>(null);
  const [hasAgreedToRisks, setHasAgreedToRisks] = useState(false);
  const [loadingScanId, setLoadingScanId] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>('');

  const loadPageData = async () => {
    const [scanData, runData] = await Promise.all([
      fetchJson<{ scans: ScanDefinition[] }>('/api/scans'),
      fetchJson<{ runs: RunItem[] }>('/api/runs'),
    ]);

    setScans(scanData.scans);
    setRuns(runData.runs);
    setForms((current) => {
      const next = { ...current };
      for (const scan of scanData.scans) {
        next[scan.id] = current[scan.id] ?? buildInitialValues(scan);
      }
      return next;
    });
  };

  useEffect(() => {
    void loadPageData().catch((error: Error) => {
      setErrorMessage(error.message);
    });
  }, []);

  const fullScan = useMemo(
    () => scans.find((scan) => scan.id === 'full-scan') ?? null,
    [scans],
  );
  const manualScans = useMemo(
    () => scans.filter((scan) => scan.id !== 'full-scan' && scan.id !== 'port-scan'),
    [scans],
  );

  const updateField = (scanId: string, fieldName: string, value: string) => {
    setForms((current) => ({
      ...current,
      [scanId]: {
        ...(current[scanId] ?? {}),
        [fieldName]: value,
      },
    }));
  };

  const submitScan = async (scanId: string, event?: FormEvent) => {
    event?.preventDefault();

    // Port scanning requires explicit confirmation due to SIEM risks
    if (scanId === 'port-scan') {
      setPendingPortScanId(scanId);
      setHasAgreedToRisks(false);
      return;
    }

    setLoadingScanId(scanId);
    setErrorMessage('');

    try {
      const payload = forms[scanId] ?? {};
      const result = await fetchJson<ScanResponse>(`/api/scans/${scanId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (result.queued) {
        setErrorMessage('Volledige scan is gestart. Resultaten verschijnen zodra de run is afgerond.');
      }

      setActiveResponse(result);
      setIsResultModalOpen(true);
      await loadPageData();

      if (result.queued) {
        window.setTimeout(() => {
          void loadPageData();
        }, 5000);
      }
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Scan actie mislukt.');
    } finally {
      setLoadingScanId(null);
    }
  };

  const executePortScan = async () => {
    if (!hasAgreedToRisks || !pendingPortScanId) return;

    setLoadingScanId(pendingPortScanId);
    setErrorMessage('');
    setPendingPortScanId(null);

    try {
      const payload = forms[pendingPortScanId] ?? {};
      const result = await fetchJson<ScanResponse>(`/api/scans/${pendingPortScanId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      setActiveResponse(result);
      setIsResultModalOpen(true);
      await loadPageData();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Port scan mislukt.');
    } finally {
      setLoadingScanId(null);
      setHasAgreedToRisks(false);
    }
  };

  return (
    <div className="app-shell">
      <header className="hero">
        <div>
          <span className="eyebrow">Full stack discovery platform</span>
          <h1>Discovery Scanner Control Center</h1>
          <p>
            Voer losse scans handmatig uit met eigen input of start meteen een volledige scan pipeline
            inclusief dashboard en CSV-output.
          </p>
        </div>
        <div className="hero-card">
          <div>
            <strong>{runs.length}</strong>
            <span>Bestaande runs</span>
          </div>
          <div>
            <strong>{manualScans.length}</strong>
            <span>Handmatige scanmodules</span>
          </div>
        </div>
      </header>

      {errorMessage ? <div className="alert error">{errorMessage}</div> : null}

      {fullScan ? (
        <section className="panel highlight">
          <div className="panel-header">
            <div>
              <span className="section-label">Quick start</span>
              <h2>{fullScan.title}</h2>
              <p>{fullScan.description}</p>
            </div>
            <button
              className="primary-button"
              type="button"
              onClick={() => {
                void submitScan(fullScan.id);
              }}
              disabled={loadingScanId === fullScan.id}
            >
              {loadingScanId === fullScan.id ? 'Volledige scan draait…' : 'Start volledige scan'}
            </button>
          </div>
          <form className="form-grid four-columns" onSubmit={(event) => void submitScan(fullScan.id, event)}>
            {fullScan.fields.map((field) => (
              <FieldRenderer
                key={field.name}
                field={field}
                value={forms[fullScan.id]?.[field.name] ?? ''}
                runs={runs}
                onChange={(value) => updateField(fullScan.id, field.name, value)}
              />
            ))}
          </form>
        </section>
      ) : null}

      <section className="content-grid">
        <div className="stack">
          <section className="panel">
            <div className="panel-header compact">
              <div>
                <span className="section-label">Manual scans</span>
                <h2>Losse scanmodules</h2>
              </div>
            </div>
            <div className="card-grid">
              {manualScans.map((scan) => (
                <form
                  key={scan.id}
                  className={`scan-card${scan.id === 'port-scan' ? ' scan-card-wide' : ''}`}
                  onSubmit={(event) => void submitScan(scan.id, event)}
                >
                  <div className="scan-card-header">
                    <div>
                      <h3>{scan.title}</h3>
                      <p>{scan.description}</p>
                    </div>
                    <button className="secondary-button" type="submit" disabled={loadingScanId === scan.id}>
                      {loadingScanId === scan.id ? 'Bezig…' : 'Uitvoeren'}
                    </button>
                  </div>
                  <div className="form-grid">
                    {scan.fields.map((field) => (
                      <FieldRenderer
                        key={field.name}
                        field={field}
                        value={forms[scan.id]?.[field.name] ?? ''}
                        runs={runs}
                        onChange={(value) => updateField(scan.id, field.name, value)}
                      />
                    ))}
                  </div>
                </form>
              ))}
            </div>
          </section>

          <section className="panel">
            <div className="panel-header compact">
              <div>
                <span className="section-label">Runs</span>
                <h2>Recente resultaten</h2>
              </div>
            </div>
            <div className="runs-list">
              {runs.length === 0 ? <p className="muted">Nog geen scanresultaten gevonden.</p> : null}
              {runs.map((run) => {
                const dashboardUrl = run.dashboardUrl;
                const domain = typeof run.summary?.domain === 'string' ? run.summary.domain : run.id;
                const subdomainsCount = typeof run.summary?.subdomains_count === 'number' ? run.summary.subdomains_count : null;
                const riskCount = typeof run.summary?.high_or_critical_risk_count === 'number'
                  ? run.summary.high_or_critical_risk_count
                  : null;

                return (
                  <article className="run-card" key={run.id}>
                    <div className="run-card-main">
                      <div>
                        <h3>{domain}</h3>
                        <p className="muted small">{run.id}</p>
                      </div>
                      <span className="pill">{new Date(run.modifiedAt).toLocaleString()}</span>
                    </div>
                    <div className="run-metrics">
                      {run.summary?.action === 'intelx-search' ? (
                        <>
                          <div>
                            <strong>{typeof run.summary?.result_count === 'number' ? run.summary.result_count : '—'}</strong>
                            <span>Credential hits</span>
                          </div>
                          <div>
                            <strong>{typeof run.summary?.days === 'number' ? `${run.summary.days}d` : '—'}</strong>
                            <span>Lookback</span>
                          </div>
                          <div>
                            <strong>{run.files.length}</strong>
                            <span>Bestanden</span>
                          </div>
                        </>
                      ) : (
                        <>
                          <div>
                            <strong>{subdomainsCount ?? '—'}</strong>
                            <span>Subdomeinen</span>
                          </div>
                          <div>
                            <strong>{riskCount ?? '—'}</strong>
                            <span>High/Critical</span>
                          </div>
                          <div>
                            <strong>{run.files.length}</strong>
                            <span>Bestanden</span>
                          </div>
                        </>
                      )}
                    </div>
                    <div className="run-actions">
                      {dashboardUrl ? (
                        <button
                          className="link-button"
                          type="button"
                          onClick={() => {
                            void openProtectedFile(dashboardUrl, 'dashboard.html').catch((error: Error) => {
                              setErrorMessage(error.message);
                            });
                          }}
                        >
                          Dashboard openen
                        </button>
                      ) : null}
                    </div>
                    <div className="file-list">
                      {run.files.slice(0, 8).map((file) => (
                        <button
                          key={file.url}
                          type="button"
                          className="file-pill"
                          onClick={() => {
                            void openProtectedFile(file.url, file.name).catch((error: Error) => {
                              setErrorMessage(error.message);
                            });
                          }}
                        >
                          <span>{file.name}</span>
                          <small>{formatBytes(file.size)}</small>
                        </button>
                      ))}
                    </div>
                  </article>
                );
              })}
            </div>
          </section>
        </div>

        <section className="panel sticky-panel">
          <div className="panel-header compact">
            <div>
              <span className="section-label">Response</span>
              <h2>Laatste scanresultaat</h2>
            </div>
          </div>
          {!activeResponse ? (
            <p className="muted">Voer een scan uit om de JSON-respons en gegenereerde run hier te zien.</p>
          ) : (
            <ScanResultView response={activeResponse} />
          )}
        </section>
      </section>

      {isResultModalOpen && activeResponse ? (
        <div
          className="result-modal-backdrop"
          role="presentation"
          onClick={() => setIsResultModalOpen(false)}
        >
          <section
            className="result-modal"
            role="dialog"
            aria-modal="true"
            aria-label="Scanresultaat"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="result-modal-header">
              <div>
                <span className="section-label">Resultaat</span>
                <h2>Scan succesvol uitgevoerd</h2>
                <p className="muted">Actie: {String(activeResponse.action ?? 'onbekend')} · Run: {String(activeResponse.runId ?? '—')}</p>
              </div>
              <button className="secondary-button" type="button" onClick={() => setIsResultModalOpen(false)}>
                Sluiten
              </button>
            </div>
            <div className="result-modal-content">
              <ScanResultView response={activeResponse} isInModal />
            </div>
          </section>
        </div>
      ) : null}

      {pendingPortScanId ? (
        <div
          className="risk-warning-backdrop"
          role="presentation"
          onClick={() => {
            setPendingPortScanId(null);
            setHasAgreedToRisks(false);
          }}
        >
          {/* <section
            className="risk-warning-modal"
            role="dialog"
            aria-modal="true"
            aria-label="Waarschuwing"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="risk-warning-header">
              <h2>⚠️ Waarschuwing: Actieve Port Scan</h2>
              <p>
                Deze scan voert een <strong>actieve netwerkverkenning</strong> uit met Nmap.
              </p>
            </div>
            <div className="risk-warning-content">
              <ul>
                <li><strong>SIEM/IDS alerts:</strong> Firewalls en monitoingsystemen kunnen deze activiteit detecteren en blocken.</li>
                <li><strong>Performance impact:</strong> Kan netwerkverkeer verstoren op het doelnetwerk.</li>
                <li><strong>Autorisatie:</strong> Je moet expliciete toestemming hebben om dit doel te scannen.</li>
                <li><strong>Logs:</strong> Alle activiteit kan worden vastgelegd en geautoriseerd.</li>
              </ul>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={hasAgreedToRisks}
                  onChange={(e) => setHasAgreedToRisks(e.target.checked)}
                />
                <span>Ik begrijp de risico's en heb autorisatie om dit doel te scannen.</span>
              </label>
            </div>

            <div className="risk-warning-actions">
              <button
                className="secondary-button"
                type="button"
                onClick={() => {
                  setPendingPortScanId(null);
                  setHasAgreedToRisks(false);
                }}
              >
                Annuleren
              </button>
              <button
                className="primary-button"
                type="button"
                disabled={!hasAgreedToRisks}
                onClick={() => void executePortScan()}
              >
                Scan starten
              </button>
            </div>
          </section> */}
        </div>
      ) : null}
    </div>
  );
}

type FieldRendererProps = {
  field: ScanField;
  value: string;
  runs: RunItem[];
  onChange: (value: string) => void;
};

function FieldRenderer({ field, value, runs, onChange }: FieldRendererProps) {
  const commonProps = {
    id: field.name,
    name: field.name,
    value,
    required: field.required,
    placeholder: field.placeholder,
    onChange: (event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
      onChange(event.target.value);
    },
  };

  return (
    <label className={`field field-${field.type}`}>
      <span>{field.label}</span>
      {field.type === 'textarea' ? <textarea rows={5} {...commonProps} /> : null}
      {field.type === 'run-select' ? (
        <select {...commonProps}>
          <option value="">Geen run geselecteerd</option>
          {runs.map((run) => (
            <option key={run.id} value={run.id}>
              {run.id}
            </option>
          ))}
        </select>
      ) : null}
      {field.type === 'select' ? (
        <select {...commonProps}>
          {(field.options ?? []).map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      ) : null}
      {field.type !== 'textarea' && field.type !== 'run-select' && field.type !== 'select' ? (
        <input type={field.type} {...commonProps} />
      ) : null}
      {field.description ? <small>{field.description}</small> : null}
      {field.options?.some((option) => option.description) ? (
        <ul className="field-help-list">
          {field.options.map((option) => (
            option.description ? (
              <li key={option.value}>
                <strong>{option.label}:</strong> {option.description}
              </li>
            ) : null
          ))}
        </ul>
      ) : null}
      {field.helpItems?.length ? (
        <ul className="field-help-list">
          {field.helpItems.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : null}
    </label>
  );
}

function ScanResultView({ response, isInModal = false }: { response: ScanResponse; isInModal?: boolean }) {
  if (response.action === 'intelx-search') {
    return <IntelxResultPanel response={response} />;
  }
  if (response.action === 'port-scan') {
    return <PortScanResultPanel response={response} />;
  }
  return (
    <>
      <div className="response-meta">
        <div>
          <span>Run ID</span>
          <strong>{String(response.runId ?? '—')}</strong>
        </div>
        <div>
          <span>Status</span>
          <strong>{response.ok === false ? 'Mislukt' : 'Geslaagd'}</strong>
        </div>
      </div>
      <pre className={`response-box${isInModal ? ' response-box-modal' : ''}`}>{toPrettyJson(response)}</pre>
    </>
  );
}

function IntelxResultPanel({ response }: { response: ScanResponse }) {
  const rows = response.previewRows ?? [];
  const allKeys = Array.from(
    new Set(rows.flatMap((row) => Object.keys(row))),
  ).filter((key) => !['term'].includes(key));
  const visibleKeys = ['name', 'bucket', 'date', 'added', 'type', 'media'].filter((k) => allKeys.includes(k));
  const cols = visibleKeys.length > 0 ? visibleKeys : allKeys.slice(0, 6);

  return (
    <div className="intelx-result">
      <div className="response-meta">
        <div>
          <span>Run ID</span>
          <strong>{String(response.runId ?? '—')}</strong>
        </div>
        <div>
          <span>Zoekterm</span>
          <strong>{String(response.term ?? '—')}</strong>
        </div>
        <div>
          <span>Gevonden</span>
          <strong className={Number(response.resultCount) > 0 ? 'hit' : ''}>{String(response.resultCount ?? 0)} resultaten</strong>
        </div>
        <div>
          <span>Lookback</span>
          <strong>{String(response.days ?? '—')} dagen</strong>
        </div>
      </div>

      {rows.length > 0 ? (
        <div className="intelx-table-wrapper">
          <table className="intelx-table">
            <thead>
              <tr>
                {cols.map((col) => <th key={col}>{col}</th>)}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={index}>
                  {cols.map((col) => (
                    <td key={col}>{String(row[col] ?? '')}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted">Geen resultaten gevonden in de opgegeven periode.</p>
      )}
    </div>
  );
}

function PortScanResultPanel({ response }: { response: ScanResponse }) {
  const rows = response.previewRows ?? [];

  return (
    <div className="port-scan-result">
      <div className="response-meta">
        <div>
          <span>Doel</span>
          <strong>{String(response.target ?? '—')}</strong>
        </div>
        <div>
          <span>Scan type</span>
          <strong>{String(response.scanType ?? '—')}</strong>
        </div>
        <div>
          <span>Open poorten</span>
          <strong className="open-badge">{String(response.openCount ?? 0)}</strong>
        </div>
        <div>
          <span>Gefilterd</span>
          <strong className="filtered-badge">{String(response.filteredCount ?? 0)}</strong>
        </div>
        <div>
          <span>Gesloten</span>
          <strong className="closed-badge">{String(response.closedCount ?? 0)}</strong>
        </div>
      </div>

      {rows.length > 0 ? (
        <div className="port-table-wrapper">
          <table className="port-table">
            <thead>
              <tr>
                <th>Host</th>
                <th>Port</th>
                <th>Protocol</th>
                <th>State</th>
                <th>Service</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={index} className={`state-${row.state}`}>
                  <td>{String(row.host ?? '')}</td>
                  <td><strong>{String(row.port ?? '')}</strong></td>
                  <td>{String(row.protocol ?? '')}</td>
                  <td className={`state-badge state-${row.state}`}>{String(row.state ?? '')}</td>
                  <td>{String(row.service ?? '')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted">Geen open of gefilterde poorten gevonden.</p>
      )}
    </div>
  );
}

export default App;
