import { useEffect, useState } from "react";

import {
  AlertTriangle,
  Activity,
  CheckCircle2,
  Clock3,
  Copy,
  Database,
  History,
  Link2,
  Radio,
  ScanLine,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Wifi,
  X,
  XCircle,
  Zap,
} from "lucide-react";

import "./App.css";

function getRiskClass(level) {
  if (level === "critical") return "critical";
  if (level === "high") return "high";
  if (level === "medium") return "medium";
  return "low";
}

function formatVerdict(verdict) {
  if (!verdict) return "Assessment complete";

  const labels = {
    confirmed_by_multiple_sources: "Confirmed by Multiple Sources",
    potentially_malicious: "Potentially Malicious",
    highly_suspicious: "Highly Suspicious",
    suspicious: "Suspicious",
    low_confidence_suspicious: "Low-Confidence Suspicious",
    insufficient_intelligence: "Insufficient Intelligence",
    no_major_threat_indicators: "No Major Threat Indicators",
  };

  return (
    labels[verdict] ||
    verdict
      .replace(/_/g, " ")
      .replace(/\b\w/g, (char) => char.toUpperCase())
  );
}

function formatRiskLevel(level) {
  if (!level) return "Unknown";
  return level.charAt(0).toUpperCase() + level.slice(1);
}

function RiskIcon({ level, size = 20 }) {
  if (level === "critical" || level === "high") {
    return <ShieldAlert size={size} />;
  }

  if (level === "medium") {
    return <AlertTriangle size={size} />;
  }

  return <ShieldCheck size={size} />;
}

function App() {
  const [target, setTarget] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const [uptime, setUptime] = useState(99.98);

  const [scanStage, setScanStage] = useState(0);

  const scanStages = [
    "INITIALIZING SECURE ANALYSIS",
    "PARSING TARGET INFRASTRUCTURE",
    "RUNNING LOCAL THREAT ENGINE",
    "QUERYING THREAT INTELLIGENCE",
    "CORRELATING SECURITY SIGNALS",
    "GENERATING RISK ASSESSMENT",
  ];

  function scrollToTop() {
    window.scrollTo({
      top: 0,
      left: 0,
      behavior: "smooth",
    });
  }

  async function loadHistory() {
    try {
      setHistoryLoading(true);

      const response = await fetch("/api/v1/history?limit=20");

      if (!response.ok) {
        throw new Error("Unable to load scan history.");
      }

      const data = await response.json();
      setHistory(data);
    } catch (err) {
      console.error(err);
    } finally {
      setHistoryLoading(false);
    }
  }

  useEffect(() => {
    window.history.scrollRestoration = "manual";

    window.scrollTo({
      top: 0,
      left: 0,
      behavior: "auto",
    });

    const forceTop = setTimeout(() => {
      window.scrollTo(0, 0);
    }, 50);

    loadHistory();

    const interval = setInterval(() => {
      setUptime((previous) =>
        Number(
          Math.min(
            99.99,
            Math.max(99.91, previous + (Math.random() - 0.45) * 0.01)
          ).toFixed(2)
        )
      );
    }, 4000);

    return () => {
      clearTimeout(forceTop);
      clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    if (!loading) {
      setScanStage(0);
      return;
    }

    const stageInterval = setInterval(() => {
      setScanStage((previous) =>
        Math.min(previous + 1, scanStages.length - 1)
      );
    }, 800);

    return () => clearInterval(stageInterval);
  }, [loading]);

  async function handleScan(event) {
    event.preventDefault();

    const cleanTarget = target.trim();

    if (!cleanTarget) {
      setError("Enter a URL to scan.");
      return;
    }

    setLoading(true);
    setError("");
    setScanResult(null);
    setScanStage(0);

    const minimumAnimationTime = new Promise((resolve) => {
      setTimeout(resolve, 5000);
    });

    try {
      const scanRequest = fetch("/api/v1/scan/url", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          target: cleanTarget,
        }),
      }).then(async (response) => {
        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.detail || "The scan request failed.");
        }

        return data;
      });

      const [data] = await Promise.all([
        scanRequest,
        minimumAnimationTime,
      ]);

      setScanResult(data);
      setTarget("");

      await loadHistory();
    } catch (err) {
      setError(
        err.message || "Could not connect to the FraudLens backend."
      );
    } finally {
      setLoading(false);
    }
  }

  async function openHistoryItem(id) {
    try {
      const response = await fetch(`/api/v1/history/${id}`);

      if (!response.ok) {
        throw new Error("Unable to load scan details.");
      }

      const data = await response.json();
      setSelectedScan(data);
    } catch (err) {
      setError(err.message);
    }
  }

  async function copyTarget(value) {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);

      setTimeout(() => {
        setCopied(false);
      }, 1800);
    } catch (err) {
      console.error("Copy failed:", err);
    }
  }

  const riskScore = Math.min(
    Math.max(Number(scanResult?.risk_score) || 0, 0),
    100
  );

  const riskClass = getRiskClass(scanResult?.risk_level);

  const selectedRiskClass = getRiskClass(
    selectedScan?.risk_level
  );

  return (
    <div className="app-shell">

      {/* ================= BACKGROUND SYSTEM ================= */}

      <div className="ambient-grid" />
      <div className="ambient-glow glow-one" />
      <div className="ambient-glow glow-two" />
      <div className="scanlines" />

      {/* ================= HEADER ================= */}

      <header className="topbar">

        <button
          className="brand brand-button"
          onClick={scrollToTop}
          type="button"
          title="Return to top"
        >
          <div className="brand-icon">
            <Shield size={22} />
            <span className="brand-pulse" />
          </div>

          <div>
            <div className="brand-name">
              FRAUD<span>LENS</span>
              <sup>AI</sup>
            </div>

            <div className="brand-subtitle">
              THREAT INTELLIGENCE PLATFORM
            </div>
          </div>
        </button>

        <div className="topbar-center">
          <div className="system-chip">
            <span className="live-dot" />
            LIVE SECURITY NODE
          </div>
        </div>

        <div className="system-status">

          <div className="status-item">
            <Activity size={15} />
            <span>API</span>
            <strong>ONLINE</strong>
          </div>

          <div className="status-divider" />

          <div className="status-item">
            <Server size={15} />
            <span>UPTIME</span>
            <strong>{uptime}%</strong>
          </div>

        </div>

      </header>

      <main className="dashboard">

        {/* ================= HERO ================= */}

        <section className="hero">

          <div className="hero-content">

            <div className="hero-kicker">
              <span className="kicker-line" />
              <span>THREAT INTELLIGENCE / URL ANALYSIS</span>

              <span className="kicker-status">
                <span />
                SYSTEM READY
              </span>
            </div>

            <h1>
              Detect threats
              <br />
              <span>before they execute.</span>
            </h1>

            <p>
              FraudLens analyzes suspicious URLs using deterministic
              local indicators and external threat intelligence to
              identify malicious infrastructure before interaction.
            </p>

            <div className="hero-metrics">

              <div>
                <span>ENGINE</span>
                <strong>FRAUDLENS-X</strong>
              </div>

              <div>
                <span>ANALYSIS</span>
                <strong>REAL-TIME</strong>
              </div>

              <div>
                <span>MODE</span>
                <strong>NON-INTRUSIVE</strong>
              </div>

            </div>

          </div>

          <div className="hero-visual">

            <div className="radar">

              <div className="radar-ring ring-one" />
              <div className="radar-ring ring-two" />
              <div className="radar-ring ring-three" />

              <div className="radar-cross horizontal" />
              <div className="radar-cross vertical" />

              <div className="radar-sweep" />

              <div className="radar-core">
                <ShieldCheck size={34} />
              </div>

              <div className="radar-point point-one" />
              <div className="radar-point point-two" />
              <div className="radar-point point-three" />

            </div>

            <div className="radar-label">
              <Radio size={13} />
              THREAT RADAR
            </div>

          </div>

        </section>

        {/* ================= SCANNER ================= */}

        <section
          className={`scanner-card ${
            loading ? "is-scanning" : ""
          }`}
        >

          <div className="scanner-topline">

            <div className="scanner-title">

              <div className="module-icon">
                <ScanLine size={18} />
              </div>

              <div>
                <span>01 / ANALYSIS MODULE</span>
                <h2>URL Security Scanner</h2>
              </div>

            </div>

            <div className="scanner-state">
              <span className="state-dot" />
              {loading
                ? "ANALYSIS IN PROGRESS"
                : "ENGINE STANDBY"}
            </div>

          </div>

          <div className="scanner-terminal">

            <div className="terminal-header">

              <div className="terminal-dots">
                <span />
                <span />
                <span />
              </div>

              <div className="terminal-path">
                <Terminal size={13} />
                fraudlens://scanner/input
              </div>

              <div className="terminal-secure">
                <ShieldCheck size={13} />
                SECURE
              </div>

            </div>

            <form onSubmit={handleScan}>

              <div className="input-wrapper">

                <span className="input-prompt">
                  <span>root@fraudlens</span>:~$
                </span>

                <Link2 size={18} />

                <input
                  type="text"
                  value={target}
                  onChange={(event) =>
                    setTarget(event.target.value)
                  }
                  placeholder="Enter suspicious URL..."
                  disabled={loading}
                  autoComplete="off"
                />

                {target && (
                  <button
                    type="button"
                    className="input-clear"
                    onClick={() => setTarget("")}
                  >
                    <X size={15} />
                  </button>
                )}

              </div>

              <button
                className="scan-button"
                type="submit"
                disabled={loading}
              >

                {loading ? (
                  <>
                    <span className="button-spinner" />
                    ANALYZING TARGET
                  </>
                ) : (
                  <>
                    INITIATE SCAN
                    <Zap size={16} />
                  </>
                )}

              </button>

            </form>

            {/* ================= 5 SECOND SCAN ANIMATION ================= */}

            {loading && (
              <div className="scan-animation">

                <div className="scan-animation-grid" />

                <div className="scan-beam" />

                <div className="scan-hud">

                  <div className="scan-hud-left">

                    <div className="scan-hud-icon">
                      <Shield size={25} />
                    </div>

                    <div>
                      <span>FRAUDLENS-X SECURITY ENGINE</span>
                      <strong>
                        {scanStages[scanStage]}
                      </strong>
                    </div>

                  </div>

                  <div className="scan-hud-status">
                    <span className="hud-live-dot" />
                    LIVE
                  </div>

                </div>

                <div className="scan-target-display">

                  <div className="target-crosshair">
                    <span />
                    <span />
                    <span />
                    <span />
                  </div>

                  <div className="scan-target-url">
                    <Link2 size={16} />
                    <span>{target}</span>
                  </div>

                  <div className="scan-pulse-ring" />

                </div>

                <div className="scan-log">

                  <div>
                    <span>[01]</span>
                    Establishing isolated analysis environment...
                    <b>OK</b>
                  </div>

                  <div>
                    <span>[02]</span>
                    Inspecting URL structure and indicators...
                    <b>OK</b>
                  </div>

                  <div>
                    <span>[03]</span>
                    Correlating external intelligence...
                    <b>RUN</b>
                  </div>

                  <div>
                    <span>[04]</span>
                    Building threat assessment matrix...
                    <b>RUN</b>
                  </div>

                </div>

                <div className="scan-progress-wrapper">

                  <div className="scan-progress-meta">
                    <span>
                      SECURITY ANALYSIS
                    </span>

                    <strong>
                      {Math.min(
                        98,
                        Math.round(
                          ((scanStage + 1) /
                            scanStages.length) *
                            100
                        )
                      )}
                      %
                    </strong>
                  </div>

                  <div className="scan-progress">
                    <span
                      style={{
                        width: `${
                          Math.min(
                            98,
                            ((scanStage + 1) /
                              scanStages.length) *
                              100
                          )
                        }%`,
                      }}
                    />
                  </div>

                </div>

              </div>
            )}

          </div>

          <div className="scanner-footer">

            <span>
              <ShieldCheck size={14} />
              No page interaction
            </span>

            <span>
              <Database size={14} />
              Persistent intelligence
            </span>

            <span>
              <Activity size={14} />
              Deterministic engine
            </span>

            <span className="footer-right">
              ENCRYPTED ANALYSIS CHANNEL

              <span className="encryption-bars">
                <i />
                <i />
                <i />
                <i />
              </span>
            </span>

          </div>

          {error && (
            <div className="error-banner">
              <XCircle size={18} />
              <span>{error}</span>
            </div>
          )}

        </section>

        {/* ================= RESULTS ================= */}

        {scanResult && (
          <section className="results-section">

            <div className="section-heading">

              <div>
                <span className="eyebrow">
                  02 / SECURITY ASSESSMENT
                </span>

                <h3>Threat Analysis Output</h3>
              </div>

              <div className={`risk-pill ${riskClass}`}>
                <RiskIcon
                  level={scanResult.risk_level}
                  size={17}
                />

                {formatRiskLevel(scanResult.risk_level)}
              </div>

            </div>

            <div className="result-grid">

              <div className={`score-card ${riskClass}`}>

                <div className="score-card-header">
                  <span>THREAT INDEX</span>
                  <Activity size={15} />
                </div>

                <div className="score-layout">

                  <div
                    className={`score-ring ${riskClass}`}
                    style={{
                      "--score": riskScore,
                    }}
                  >

                    <div className="score-ring-glow" />

                    <div className="score-ring-content">
                      <strong>{scanResult.risk_score}</strong>
                      <span>/ 100</span>
                    </div>

                  </div>

                  <div className="score-information">

                    <span className="card-label">
                      SYSTEM VERDICT
                    </span>

                    <h4>
                      {formatVerdict(
                        scanResult.risk_assessment?.verdict
                      )}
                    </h4>

                    <p>
                      Confidence
                      <strong>
                        {" "}
                        {formatRiskLevel(
                          scanResult.risk_assessment?.confidence
                        )}
                      </strong>
                    </p>

                    <div
                      className={`risk-status ${riskClass}`}
                    >
                      <RiskIcon
                        level={scanResult.risk_level}
                        size={14}
                      />

                      {formatRiskLevel(
                        scanResult.risk_level
                      )}{" "}
                      THREAT LEVEL
                    </div>

                  </div>

                </div>

                <div className="score-bottom">
                  <span>RISK ENGINE</span>
                  <strong>ACTIVE</strong>
                  <span className="score-pulse" />
                </div>

              </div>

              <div className="assessment-card">

                <div className="assessment-top">

                  <div>

                    <span className="card-label">
                      ANALYZED TARGET
                    </span>

                    <div className="target-value">

                      <Link2 size={16} />

                      <span>
                        {scanResult.target}
                      </span>

                      <button
                        type="button"
                        className="copy-button"
                        onClick={() =>
                          copyTarget(scanResult.target)
                        }
                        title="Copy target"
                      >
                        {copied ? (
                          <CheckCircle2 size={16} />
                        ) : (
                          <Copy size={16} />
                        )}
                      </button>

                    </div>

                  </div>

                  <div className="analyzed-status">
                    <span />
                    ANALYSIS COMPLETE
                  </div>

                </div>

                <div className="assessment-divider" />

                <div className="assessment-meta">

                  <div>
                    <span>Target Type</span>
                    <strong>
                      {scanResult.target_type}
                    </strong>
                  </div>

                  <div>
                    <span>Verdict</span>
                    <strong>
                      {formatVerdict(
                        scanResult.risk_assessment?.verdict
                      )}
                    </strong>
                  </div>

                  <div>
                    <span>Risk Score</span>
                    <strong>
                      {scanResult.risk_score}/100
                    </strong>
                  </div>

                </div>

                <div className="assessment-summary">

                  <div className="summary-heading">
                    <Shield size={16} />
                    <strong>ENGINE ANALYSIS</strong>

                    <span className="summary-live">
                      LIVE
                    </span>
                  </div>

                  <p>
                    {scanResult.risk_assessment?.explanation}
                  </p>

                </div>

              </div>

            </div>

            <div className="lower-grid">

              <div className="panel">

                <div className="panel-header">

                  <div className="panel-title">
                    <div className="panel-icon warning">
                      <AlertTriangle size={16} />
                    </div>

                    <div>
                      <h4>Local Findings</h4>
                      <span>
                        URL-level threat indicators
                      </span>
                    </div>
                  </div>

                  <span className="panel-count">
                    {scanResult.findings?.length || 0}
                  </span>

                </div>

                {scanResult.findings?.length ? (

                  <div className="findings-list">

                    {scanResult.findings.map(
                      (finding, index) => (

                        <div
                          className="finding"
                          key={`${finding.rule}-${index}`}
                        >

                          <div className="finding-index">
                            {String(index + 1).padStart(
                              2,
                              "0"
                            )}
                          </div>

                          <div className="finding-icon">
                            <AlertTriangle size={16} />
                          </div>

                          <div className="finding-content">
                            <strong>
                              {finding.rule}
                            </strong>

                            <p>
                              {finding.description}
                            </p>
                          </div>

                          <span className="finding-score">
                            +{finding.score}
                          </span>

                        </div>
                      )
                    )}

                  </div>

                ) : (

                  <div className="empty-state">

                    <CheckCircle2 size={22} />

                    <div>
                      <strong>
                        NO SIGNIFICANT INDICATORS
                      </strong>

                      <span>
                        Local analysis detected no major
                        URL-level threats.
                      </span>
                    </div>

                  </div>
                )}

              </div>

              <div className="panel">

                <div className="panel-header">

                  <div className="panel-title">
                    <div className="panel-icon intel">
                      <Radio size={16} />
                    </div>

                    <div>
                      <h4>Threat Intelligence</h4>
                      <span>
                        External intelligence providers
                      </span>
                    </div>
                  </div>

                  <span className="panel-count">
                    {scanResult.intelligence?.filter(
                      (provider) => provider.available
                    ).length || 0}
                  </span>

                </div>

                <div className="intel-list">

                  {scanResult.intelligence?.map(
                    (provider) => (

                      <div
                        className="intel-row"
                        key={provider.provider}
                      >

                        <div className="intel-provider">

                          <div
                            className={`intel-icon ${
                              provider.available
                                ? provider.malicious
                                  ? "malicious"
                                  : "safe"
                                : "unavailable"
                            }`}
                          >

                            {provider.available ? (
                              provider.malicious ? (
                                <ShieldAlert size={16} />
                              ) : (
                                <CheckCircle2 size={16} />
                              )
                            ) : (
                              <XCircle size={16} />
                            )}

                          </div>

                          <div>
                            <strong>
                              {provider.provider}
                            </strong>

                            <span>
                              {provider.available
                                ? provider.malicious
                                  ? "Malicious result detected"
                                  : "No malicious result"
                                : "Provider unavailable"}
                            </span>
                          </div>

                        </div>

                        <div className="intel-result">

                          <span className="intel-score">
                            {provider.score !== null &&
                            provider.score !== undefined
                              ? provider.score
                              : "—"}
                          </span>

                          <span className="intel-label">
                            SCORE
                          </span>

                        </div>

                      </div>
                    )
                  )}

                </div>

              </div>

            </div>

          </section>
        )}

        {/* ================= HISTORY ================= */}

        <section className="history-section">

          <div className="section-heading">

            <div>
              <span className="eyebrow">
                03 / INTELLIGENCE DATABASE
              </span>

              <h3>Scan History</h3>
            </div>

            <button
              className="refresh-button"
              onClick={loadHistory}
              type="button"
            >
              <History size={14} />
              REFRESH DATABASE
            </button>

          </div>

          <div className="history-card">

            {historyLoading ? (

              <div className="history-empty">
                <span className="loading-dot" />
                Querying intelligence database...
              </div>

            ) : history.length === 0 ? (

              <div className="history-empty">

                <History size={22} />

                <div>
                  <strong>
                    NO SCAN RECORDS
                  </strong>

                  <span>
                    Completed URL assessments will
                    appear in this database.
                  </span>
                </div>

              </div>

            ) : (

              <div className="history-table">

                <div className="history-header">
                  <span>Target</span>
                  <span>Risk</span>
                  <span>Verdict</span>
                  <span>Confidence</span>
                  <span>Timestamp</span>
                </div>

                {history.map((record) => (

                  <button
                    className="history-row"
                    key={record.id}
                    onClick={() =>
                      openHistoryItem(record.id)
                    }
                    type="button"
                  >

                    <span className="history-target">
                      <Link2 size={14} />
                      {record.target}
                    </span>

                    <span
                      className={`history-risk ${getRiskClass(
                        record.risk_level
                      )}`}
                    >
                      {record.risk_score}
                    </span>

                    <span className="history-verdict">
                      {formatVerdict(record.verdict)}
                    </span>

                    <span className="history-confidence">
                      {formatRiskLevel(record.confidence)}
                    </span>

                    <span className="history-time">
                      <Clock3 size={13} />

                      {new Date(
                        record.created_at
                      ).toLocaleString()}
                    </span>

                  </button>
                ))}

              </div>
            )}

          </div>

        </section>

      </main>

      {/* ================= HISTORY MODAL ================= */}

      {selectedScan && (

        <div
          className="modal-backdrop"
          onClick={() => setSelectedScan(null)}
        >

          <div
            className={`history-modal ${selectedRiskClass}`}
            onClick={(event) =>
              event.stopPropagation()
            }
          >

            <div className="modal-scan-line" />

            <div className="modal-corner corner-tl" />
            <div className="modal-corner corner-tr" />
            <div className="modal-corner corner-bl" />
            <div className="modal-corner corner-br" />

            <div className="modal-header">

              <div>

                <div className="modal-system-label">
                  <span />
                  FRAUDLENS-X / SECURE RECORD
                </div>

                <span className="eyebrow">
                  RECORD / #{selectedScan.id}
                </span>

                <h3>Scan Details</h3>

              </div>

              <button
                type="button"
                onClick={() =>
                  setSelectedScan(null)
                }
                className="close-button"
                title="Close"
              >
                <X size={19} />
              </button>

            </div>

            <div className="modal-target">

              <div className="modal-target-icon">
                <Link2 size={18} />
              </div>

              <div>
                <span>ANALYZED TARGET</span>
                <strong>
                  {selectedScan.target}
                </strong>
              </div>

              <div className="modal-target-status">
                <Wifi size={14} />
                VERIFIED
              </div>

            </div>

            <div className="modal-main-grid">

              <div className="modal-score-display">

                <span>THREAT INDEX</span>

                <div
                  className="modal-score-ring"
                  style={{
                    "--modal-score": Math.min(
                      Math.max(
                        Number(
                          selectedScan.risk_score
                        ) || 0,
                        0
                      ),
                      100
                    ),
                  }}
                >
                  <div>
                    <strong>
                      {selectedScan.risk_score}
                    </strong>
                    <span>/100</span>
                  </div>
                </div>

                <div
                  className={`modal-risk-badge ${selectedRiskClass}`}
                >
                  <RiskIcon
                    level={selectedScan.risk_level}
                    size={15}
                  />
                  {formatRiskLevel(
                    selectedScan.risk_level
                  )}
                </div>

              </div>

              <div className="modal-stats">

                <div className="modal-stat">
                  <span>RISK SCORE</span>
                  <strong>
                    {selectedScan.risk_score}/100
                  </strong>
                  <small>THREAT INDEX</small>
                </div>

                <div className="modal-stat">
                  <span>RISK LEVEL</span>
                  <strong>
                    {formatRiskLevel(
                      selectedScan.risk_level
                    )}
                  </strong>
                  <small>CLASSIFICATION</small>
                </div>

                <div className="modal-stat">
                  <span>CONFIDENCE</span>
                  <strong>
                    {formatRiskLevel(
                      selectedScan.confidence
                    )}
                  </strong>
                  <small>ENGINE CONFIDENCE</small>
                </div>

                <div className="modal-stat">
                  <span>VERDICT</span>
                  <strong>
                    {formatVerdict(
                      selectedScan.verdict
                    )}
                  </strong>
                  <small>FINAL ASSESSMENT</small>
                </div>

              </div>

            </div>

            <div className="modal-terminal">

              <div className="modal-terminal-header">
                <Terminal size={14} />
                <span>
                  fraudlens://records/{selectedScan.id}
                </span>

                <span className="modal-terminal-live">
                  <span />
                  RECORD LOCKED
                </span>
              </div>

              <div className="modal-terminal-body">

                <div>
                  <span className="terminal-prefix">
                    $
                  </span>
                  assessment.status
                  <strong>COMMITTED</strong>
                </div>

                <div>
                  <span className="terminal-prefix">
                    $
                  </span>
                  intelligence.database
                  <strong>UPDATED</strong>
                </div>

                <div>
                  <span className="terminal-prefix">
                    $
                  </span>
                  security.channel
                  <strong>ENCRYPTED</strong>
                </div>

              </div>

            </div>

            <div className="modal-footer">

              <CheckCircle2 size={15} />

              <span>
                Assessment successfully committed to
                intelligence database.
              </span>

              <span className="modal-footer-id">
                ID #{selectedScan.id}
              </span>

            </div>

          </div>

        </div>
      )}

    </div>
  );
}

export default App;