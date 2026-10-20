
import { useState } from "react";
import "./App.css";

type Alert = {
  username: string;
  sourceIp: string;
  riskScore: number;
  severity: string;
  reasons: string[];
};

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

function App() {
  const [filter, setFilter] = useState("ALL");
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [alerts, setAlerts] = useState(sampleAlerts);
  const [apiStatus, setApiStatus] = useState("Not connected");

  const visibleAlerts = alerts.filter(
    (alert) => filter === "ALL" || alert.severity === filter,
  );

  async function testBackend() {
    setApiStatus("Connecting...");
    try {
      const response = await fetch(
        "http://localhost:8081/api/detection/analyze",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify([
            ...Array.from({ length: 5 }, (_, i) => ({
              username: "test.user",
              sourceIp: "203.0.113.50",
              successful: false,
              timestamp: new Date(Date.now() - i * 1000).toISOString(),
            })),
          ]),
        },
      );

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
            <span className="live-label"><span /> MONITORING WORKSPACE</span>
            <h3>See suspicious activity.<br />Understand the risk.</h3>
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
            <small>Sample workspace data</small>
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

        <section className="alerts-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">INVESTIGATION QUEUE</p>
              <h3>Login risk alerts</h3>
              <p className="panel-subtitle">
                Demo records until you test the Java detection API.
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
                      <span className={`severity ${alert.severity.toLowerCase()}`}>
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
            <span>i</span> Sample alert records are illustrative, not real security incidents.
          </p>
        </section>

        <footer>
          <span>ThreatLens · Academic security testing project</span>
          <span>Detection decisions require analyst review</span>
        </footer>
      </main>

      {selectedAlert && (
        <div className="modal-backdrop" onClick={() => setSelectedAlert(null)}>
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
              <span className={`severity ${selectedAlert.severity.toLowerCase()}`}>
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
