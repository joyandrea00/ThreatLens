
import { useState } from "react";
import "./App.css";

type Alert = {
  username: string;
  sourceIp: string;
  riskScore: number;
  severity: string;
  reasons: string[];
};

type LoginEvent = {
  username: string;
  sourceIp: string;
  successful: boolean;
  timestamp: string;
};

const API_URL = "http://localhost:8081/api/detection/analyze";

const sampleAlerts: Alert[] = [
  {
    username: "j.smith",
    sourceIp: "203.0.113.10",
    riskScore: 85,
    severity: "HIGH",
    reasons: ["Repeated failed login attempts", "Unusual login activity"],
  },
  {
    username: "m.lee",
    sourceIp: "198.51.100.24",
    riskScore: 65,
    severity: "MEDIUM",
    reasons: ["5 failed login attempts from this IP"],
  },
  {
    username: "a.kumar",
    sourceIp: "192.0.2.18",
    riskScore: 20,
    severity: "LOW",
    reasons: ["Routine login activity"],
  },
];

const REQUIRED_COLUMNS = [
  "username",
  "sourceIp",
  "successful",
  "timestamp",
];

function parseCsvLine(line: string): string[] {
  const values: string[] = [];
  let value = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];

    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        value += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === "," && !inQuotes) {
      values.push(value.trim());
      value = "";
    } else {
      value += char;
    }
  }

  values.push(value.trim());
  return values;
}

function App() {
  const [filter, setFilter] = useState("ALL");
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>(sampleAlerts);
  const [apiStatus, setApiStatus] = useState("Not connected");

  const [csvEvents, setCsvEvents] = useState<LoginEvent[]>([]);
  const [csvErrors, setCsvErrors] = useState<string[]>([]);
  const [csvFileName, setCsvFileName] = useState("");
  const [csvMessage, setCsvMessage] = useState("");
  const [uploading, setUploading] = useState(false);

  const visibleAlerts = alerts.filter(
    (alert) => filter === "ALL" || alert.severity === filter,
  );

  async function testBackend() {
    setApiStatus("Connecting...");

    try {
      const events: LoginEvent[] = Array.from({ length: 5 }, (_, i) => ({
        username: "test.user",
        sourceIp: "203.0.113.50",
        successful: false,
        timestamp: new Date(Date.now() - i * 1000).toISOString(),
      }));

      const response = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(events),
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const result: Alert[] = await response.json();

      setAlerts((current) => [
        ...result,
        ...current.filter((a) => a.sourceIp !== "203.0.113.50"),
      ]);
      setApiStatus("Connected");
    } catch {
      setApiStatus("Connection failed — check that the backend is running");
    }
  }

  async function handleCsvFile(file?: File) {
    setCsvEvents([]);
    setCsvErrors([]);
    setCsvMessage("");

    if (!file) return;

    setCsvFileName(file.name);

    if (!file.name.toLowerCase().endsWith(".csv")) {
      setCsvErrors(["Please select a .csv file."]);
      return;
    }

    try {
      const text = await file.text();
      const lines = text
        .replace(/^\uFEFF/, "")
        .split(/\r?\n/)
        .filter((line) => line.trim() !== "");

      if (lines.length < 2) {
        setCsvErrors(["The CSV must contain a header and at least one data row."]);
        return;
      }

      const headers = parseCsvLine(lines[0]).map((header) =>
        header.trim().toLowerCase(),
      );

      const missingColumns = REQUIRED_COLUMNS.filter(
        (column) => !headers.includes(column.toLowerCase()),
      );

      if (missingColumns.length > 0) {
        setCsvErrors([
          `Missing required columns: ${missingColumns.join(", ")}`,
        ]);
        return;
      }

      const indexes = {
        username: headers.indexOf("username"),
        sourceIp: headers.indexOf("sourceip"),
        successful: headers.indexOf("successful"),
        timestamp: headers.indexOf("timestamp"),
      };

      const validEvents: LoginEvent[] = [];
      const errors: string[] = [];

      lines.slice(1).forEach((line, index) => {
        const rowNumber = index + 2;
        const values = parseCsvLine(line);

        const username = values[indexes.username]?.trim();
        const sourceIp = values[indexes.sourceIp]?.trim();
        const successfulText = values[indexes.successful]
          ?.trim()
          .toLowerCase();
        const timestamp = values[indexes.timestamp]?.trim();

        if (
          !username ||
          !sourceIp ||
          !successfulText ||
          !timestamp
        ) {
          errors.push(`Row ${rowNumber}: one or more required values are empty.`);
          return;
        }

        if (!["true", "false"].includes(successfulText)) {
          errors.push(`Row ${rowNumber}: successful must be true or false.`);
          return;
        }

        if (Number.isNaN(Date.parse(timestamp))) {
          errors.push(`Row ${rowNumber}: timestamp is not a valid date/time.`);
          return;
        }

        validEvents.push({
          username,
          sourceIp,
          successful: successfulText === "true",
          timestamp: new Date(timestamp).toISOString(),
        });
      });

      setCsvEvents(validEvents);
      setCsvErrors(errors);
      setCsvMessage(
        `Validated ${validEvents.length} event(s). ${
          errors.length
            ? `${errors.length} row(s) need correction.`
            : "All rows are valid."
        }`,
      );
    } catch {
      setCsvErrors(["Could not read this file. Please check the CSV format."]);
    }
  }

  async function submitCsvEvents() {
    if (csvEvents.length === 0) {
      setCsvMessage("There are no valid events to submit.");
      return;
    }

    setUploading(true);
    setCsvMessage("Submitting events to the detection API...");

    try {
      const response = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(csvEvents),
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const result: Alert[] = await response.json();

      setAlerts((current) => {
        const updated = [...current];
        result.forEach((newAlert) => {
          const existingIndex = updated.findIndex(
            (item) =>
              item.sourceIp === newAlert.sourceIp &&
              item.username === newAlert.username,
          );

          if (existingIndex >= 0) {
            updated[existingIndex] = newAlert;
          } else {
            updated.unshift(newAlert);
          }
        });
        return updated;
      });

      setApiStatus("Connected");
      setCsvMessage(
        `Successfully analyzed ${csvEvents.length} event(s). ${result.length} alert(s) returned by the API.`,
      );
    } catch {
      setCsvMessage(
        "Submission failed. Check that the Java backend is running on port 8081.",
      );
    } finally {
      setUploading(false);
    }
  }

  function acknowledgeAlert(alert: Alert) {
    setAlerts((current) => current.filter((item) => item !== alert));
    setSelectedAlert(null);
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">T</div>
          <div>
            <h1>ThreatLens</h1>
            <span>SECURITY ANALYTICS</span>
          </div>
        </div>

        <div className="nav-label">WORKSPACE</div>
        <button className="nav-item active">▦ Overview</button>
        <button className="nav-item" onClick={() => setFilter("ALL")}>
          ◈ Threat alerts
        </button>
        <button className="nav-item" onClick={testBackend}>
          ↗ Test detection API
        </button>
        <button
          className="nav-item"
          onClick={() =>
            document.getElementById("csv-upload")?.scrollIntoView({
              behavior: "smooth",
              block: "start",
            })
          }
        >
          ⇧ Upload login events
        </button>

        <div className="sidebar-bottom">
          <div className="status-dot" />
          <div>
            <strong>Detection service</strong>
            <p>{apiStatus}</p>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">SECURITY OPERATIONS CENTER</p>
            <h2>Threat overview</h2>
          </div>
          <div className="analyst">
            <div className="avatar">A</div>
            <div>
              <strong>Security Analyst</strong>
              <span>Local demo workspace</span>
            </div>
          </div>
        </header>

        <section className="welcome">
          <div>
            <span className="live-label">
              <span /> MONITORING WORKSPACE
            </span>
            <h3>
              See suspicious activity.
              <br />
              Understand the risk.
            </h3>
            <p>
              Review login events, investigate risk signals, and test your
              detection engine in one workspace.
            </p>
          </div>
          <div className="welcome-art" aria-hidden="true">
            <div className="orbit orbit-one" />
            <div className="orbit orbit-two" />
            <div className="shield">⌑</div>
            <div className="orbit-dot dot-one" />
            <div className="orbit-dot dot-two" />
          </div>
        </section>

        <section className="metrics">
          <div className="metric-card">
            <span>Total demo alerts</span>
            <strong>{alerts.length.toString().padStart(2, "0")}</strong>
            <small>Sample and detected alerts</small>
          </div>
          <div className="metric-card">
            <span>High risk</span>
            <strong className="high-text">
              {alerts.filter((a) => a.severity === "HIGH").length
                .toString()
                .padStart(2, "0")}
            </strong>
            <small>Requires closer review</small>
          </div>
          <div className="metric-card">
            <span>Medium risk</span>
            <strong className="medium-text">
              {alerts.filter((a) => a.severity === "MEDIUM").length
                .toString()
                .padStart(2, "0")}
            </strong>
            <small>Review recommended</small>
          </div>
          <div className="metric-card">
            <span>Detection API</span>
            <strong className="api-number">
              {apiStatus === "Connected" ? "LIVE" : "—"}
            </strong>
            <small>{apiStatus}</small>
          </div>
        </section>

        <section className="csv-panel" id="csv-upload">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">EVENT INGESTION</p>
              <h3>Upload login events</h3>
              <p className="panel-subtitle">
                Import a CSV file, validate its rows, and analyze events with
                the Java detection service.
              </p>
            </div>
          </div>

          <div className="csv-format">
            <strong>Required CSV columns</strong>
            <code>username, sourceIp, successful, timestamp</code>
            <small>
              Use true/false for successful and a valid date/time for timestamp.
            </small>
          </div>

          <label className="csv-file-label" htmlFor="csv-file">
            <span className="csv-upload-icon">⇧</span>
            <strong>Select a CSV file</strong>
            <span>Choose a login-event CSV from your computer</span>
            <input
              id="csv-file"
              type="file"
              accept=".csv,text/csv"
              onChange={(event) => handleCsvFile(event.target.files?.[0])}
            />
          </label>

          {csvFileName && (
            <p className="csv-filename">Selected file: {csvFileName}</p>
          )}

          {csvMessage && (
            <p className="csv-message" role="status">
              {csvMessage}
            </p>
          )}

          {csvErrors.length > 0 && (
            <div className="csv-errors" role="alert">
              <strong>Validation issues</strong>
              <ul>
                {csvErrors.map((error, index) => (
                  <li key={`${error}-${index}`}>{error}</li>
                ))}
              </ul>
            </div>
          )}

          {csvEvents.length > 0 && (
            <>
              <div className="csv-preview-heading">
                <div>
                  <h4>Event preview</h4>
                  <p>{csvEvents.length} valid event(s) ready for analysis</p>
                </div>
                <button
                  className="test-button"
                  onClick={submitCsvEvents}
                  disabled={uploading}
                >
                  {uploading ? "Analyzing..." : "Analyze events ↗"}
                </button>
              </div>

              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>USERNAME</th>
                      <th>SOURCE IP</th>
                      <th>SUCCESSFUL</th>
                      <th>TIMESTAMP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {csvEvents.slice(0, 5).map((event, index) => (
                      <tr key={`${event.username}-${event.timestamp}-${index}`}>
                        <td>{event.username}</td>
                        <td className="ip-cell">{event.sourceIp}</td>
                        <td>
                          <span
                            className={
                              event.successful ? "csv-success" : "csv-failure"
                            }
                          >
                            {event.successful ? "Success" : "Failed"}
                          </span>
                        </td>
                        <td>{event.timestamp}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {csvEvents.length > 5 && (
                <p className="panel-subtitle">
                  Showing the first 5 rows. All {csvEvents.length} valid events
                  will be submitted.
                </p>
              )}
            </>
          )}
        </section>

        <section className="alerts-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">INVESTIGATION QUEUE</p>
              <h3>Login risk alerts</h3>
              <p className="panel-subtitle">
                Sample records are illustrative; detected alerts come from the
                Java API.
              </p>
            </div>
            <button className="test-button" onClick={testBackend}>
              Run detection test ↗
            </button>
          </div>

          <div className="filter-row">
            {["ALL", "HIGH", "MEDIUM", "LOW"].map((item) => (
              <button
                key={item}
                className={`filter-button ${filter === item ? "selected" : ""}`}
                onClick={() => setFilter(item)}
              >
                {item === "ALL" ? "All alerts" : item}
              </button>
            ))}
            <span className="result-count">{visibleAlerts.length} records</span>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ACCOUNT</th>
                  <th>SOURCE IP</th>
                  <th>RISK SCORE</th>
                  <th>SEVERITY</th>
                  <th>REVIEW</th>
                </tr>
              </thead>
              <tbody>
                {visibleAlerts.map((alert, index) => (
                  <tr key={`${alert.sourceIp}-${alert.username}-${index}`}>
                    <td>
                      <div className="account-cell">
                        <div className="account-avatar">
                          {alert.username.charAt(0).toUpperCase()}
                        </div>
                        <strong>{alert.username}</strong>
                      </div>
                    </td>
                    <td className="ip-cell">{alert.sourceIp}</td>
                    <td>
                      <div className="score-cell">
                        <div className="score-track">
                          <div
                            className={`score-fill ${alert.severity.toLowerCase()}`}
                            style={{ width: `${alert.riskScore}%` }}
                          />
                        </div>
                        <strong>{alert.riskScore}</strong>
                      </div>
                    </td>
                    <td>
                      <span
                        className={`severity ${alert.severity.toLowerCase()}`}
                      >
                        <span /> {alert.severity}
                      </span>
                    </td>
                    <td>
                      <button
                        className="view-button"
                        onClick={() => setSelectedAlert(alert)}
                      >
                        Investigate →
                      </button>
                    </td>
                  </tr>
                ))}
                {visibleAlerts.length === 0 && (
                  <tr>
                    <td colSpan={5} className="empty-state">
                      No alerts match this filter.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <p className="demo-note">
            <span>i</span> Sample alert records are illustrative, not real
            security incidents.
          </p>
        </section>

        <footer>
          <span>ThreatLens · Academic security testing project</span>
          <span>Detection decisions require analyst review</span>
        </footer>
      </main>

      {selectedAlert && (
        <div
          className="modal-backdrop"
          onClick={() => setSelectedAlert(null)}
        >
          <section
            className="investigation-modal"
            onClick={(event) => event.stopPropagation()}
          >
            <button
              className="modal-close"
              onClick={() => setSelectedAlert(null)}
            >
              ×
            </button>
            <p className="eyebrow">ALERT INVESTIGATION</p>
            <h3>{selectedAlert.username}</h3>
            <p className="ip-cell">{selectedAlert.sourceIp}</p>
            <div className="modal-score">
              <span>Risk score</span>
              <strong>{selectedAlert.riskScore}/100</strong>
              <span
                className={`severity ${selectedAlert.severity.toLowerCase()}`}
              >
                {selectedAlert.severity}
              </span>
            </div>
            <h4>Detection evidence</h4>
            <ul>
              {selectedAlert.reasons.map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
            <p className="modal-disclaimer">
              This is a heuristic risk signal, not proof of account compromise.
            </p>
            <button
              className="test-button full-button"
              onClick={() => acknowledgeAlert(selectedAlert)}
            >
              Acknowledge and remove from queue
            </button>
          </section>
        </div>
      )}
    </div>
  );
}

export default App;
