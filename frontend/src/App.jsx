import { useEffect, useMemo, useState } from "react";

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

const SCAN_STAGES = [
  "INITIALIZING FRAUDLENS-X",
  "NORMALIZING TARGET",
  "ANALYZING URL STRUCTURE",
  "CHECKING LOCAL INDICATORS",
  "QUERYING THREAT INTELLIGENCE",
  "CORRELATING SIGNALS",
  "GENERATING RISK ASSESSMENT",
  "SCAN COMPLETE",
];

const SCAN_PROGRESS = [7, 24, 51, 78, 92, 96, 99, 100];

const SCAN_STAGE_TIMES = [
  0,
  650,
  1300,
  1950,
  2750,
  3500,
  4250,
  5000,
];

function parseTargetParts(value) {
  if (!value) return [];

  try {
    const parsed = new URL(
      /^https?:\/\//i.test(value) ? value : `https://${value}`
    );

    const params = parsed.search ? parsed.search.slice(1) : "";
    const path = parsed.pathname || "/";

    return [
      {
        key: "PROTOCOL",
        value: `${parsed.protocol.replace(":", "").toUpperCase()}://`,
        status: "PARSED",
      },
      {
        key: "DOMAIN",
        value: parsed.hostname || "—",
        status: "PARSED",
      },
      {
        key: "PORT",
        value: parsed.port || "DEFAULT",
        status: parsed.port ? "EXPLICIT" : "DEFAULT",
      },
      {
        key: "PATH",
        value: path,
        status: path === "/" ? "ROOT" : "PARSED",
      },
      {
        key: "PARAMETERS",
        value: params || "NONE",
        status: params ? "PRESENT" : "NONE",
      },
      {
        key: "FRAGMENT",
        value: parsed.hash ? parsed.hash.slice(1) : "NONE",
        status: parsed.hash ? "PRESENT" : "NONE",
      },
      {
        key: "REDIRECTS",
        value: "NOT REPORTED",
        status: "BACKEND DATA",
      },
    ];
  } catch {
    return [
      {
        key: "TARGET",
        value,
        status: "RAW INPUT",
      },
    ];
  }
}

function confidencePercent(value) {
  if (
    typeof value === "number" &&
    Number.isFinite(value)
  ) {
    return Math.max(0, Math.min(100, value));
  }

  const normalized = String(value || "").toLowerCase();

  if (normalized === "very high" || normalized === "critical") {
    return 95;
  }

  if (normalized === "high") {
    return 85;
  }

  if (normalized === "medium") {
    return 65;
  }

  if (normalized === "low") {
    return 40;
  }

  return null;
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
  const [showIntro, setShowIntro] = useState(true);

  const [scanStage, setScanStage] = useState(0);
  const [scanProgress, setScanProgress] = useState(0);
  const [displayScore, setDisplayScore] = useState(0);

  const [traceOpen, setTraceOpen] = useState(false);
  const [traceStage, setTraceStage] = useState(-1);
  const [resultRevealed, setResultRevealed] = useState(false);

  function scrollToTop() {
    window.scrollTo({
      top: 0,
      left: 0,
      behavior: "smooth",
    });
  }

  async function loadHistory() {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    try {
      setHistoryLoading(true);

      const response = await fetch("/api/v1/history?limit=20", {
        method: "GET",
        signal: controller.signal,
        cache: "no-store",
      });

      if (!response.ok) {
        throw new Error(`History API returned ${response.status}.`);
      }

      const data = await response.json();

      // The backend returns an array. Keep this defensive for wrapped APIs.
      const records = Array.isArray(data)
        ? data
        : Array.isArray(data?.items)
          ? data.items
          : null;

      if (records === null) {
        throw new Error("History API returned an invalid response.");
      }

      setHistory(records);
      return true;
    } catch (err) {
      // History is secondary UI. A failed history request must NEVER make
      // the scanner look broken or display a red error banner on page load.
      console.warn("Scan history unavailable:", err);
      return false;
    } finally {
      clearTimeout(timeout);
      setHistoryLoading(false);
    }
  }

  function addLocalHistoryRecord(data) {
    if (!data) return;

    const localRecord = {
      id: `local-${Date.now()}`,
      target: data.target,
      target_type: data.target_type,
      risk_score: data.risk_score,
      risk_level: data.risk_level,
      verdict: data.risk_assessment?.verdict || "Assessment complete",
      confidence: data.risk_assessment?.confidence || "Unknown",
      created_at: new Date().toISOString(),
      local: true,
    };

    setHistory((previous) => [
      localRecord,
      ...previous.filter((record) => record.target !== localRecord.target),
    ]);
  }

  useEffect(() => {
    window.history.scrollRestoration = "manual";

    const introTimer = setTimeout(() => {
      setShowIntro(false);
    }, 1850);

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
            Math.max(
              99.91,
              previous + (Math.random() - 0.45) * 0.01
            )
          ).toFixed(2)
        )
      );
    }, 4000);

    return () => {
      clearTimeout(introTimer);
      clearTimeout(forceTop);
      clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    if (!loading) {
      setScanStage(0);
      setScanProgress(0);
      return;
    }

    const startedAt = performance.now();

    const tick = () => {
      const elapsed = performance.now() - startedAt;

      let stage = 0;

      for (let i = 0; i < SCAN_STAGE_TIMES.length; i += 1) {
        if (elapsed >= SCAN_STAGE_TIMES[i]) {
          stage = i;
        }
      }

      setScanStage(stage);
      setScanProgress(SCAN_PROGRESS[stage]);
    };

    tick();

    const interval = setInterval(tick, 80);

    return () => clearInterval(interval);
  }, [loading]);

  useEffect(() => {
    if (!scanResult) {
      setDisplayScore(0);
      setResultRevealed(false);
      return;
    }

    const targetScore = Math.min(
      Math.max(Number(scanResult.risk_score) || 0, 0),
      100
    );

    setDisplayScore(0);
    setResultRevealed(false);

    const startedAt = performance.now();
    const duration = 1050;

    const timer = setInterval(() => {
      const progress = Math.min(
        1,
        (performance.now() - startedAt) / duration
      );

      const eased = 1 - Math.pow(1 - progress, 3);

      setDisplayScore(
        Math.round(targetScore * eased)
      );

      if (progress >= 1) {
        clearInterval(timer);
        setResultRevealed(true);
      }
    }, 32);

    return () => clearInterval(timer);
  }, [scanResult]);

  useEffect(() => {
    if (!traceOpen) {
      setTraceStage(-1);
      return;
    }

    const interval = setInterval(() => {
      setTraceStage((previous) =>
        Math.min(previous + 1, 7)
      );
    }, 420);

    return () => clearInterval(interval);
  }, [traceOpen]);

  async function handleScan(event) {
    event.preventDefault();

    let cleanTarget = target.trim();

    // The input starts with https://. If the user pasted a URL without a
    // protocol, normalize it before sending it to the backend.
    if (!/^https?:\/\//i.test(cleanTarget)) {
      cleanTarget = `https://${cleanTarget}`;
    }

    if (
      !cleanTarget ||
      cleanTarget === "https://" ||
      cleanTarget === "http://"
    ) {
      setError("Enter a complete URL to scan.");
      return;
    }

    setLoading(true);
    setError("");
    setScanResult(null);
    setScanStage(0);
    setScanProgress(SCAN_PROGRESS[0]);
    setTraceOpen(false);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);

    const minimumAnimationTime = new Promise((resolve) =>
      setTimeout(resolve, 5000)
    );

    try {
      const scanRequest = fetch("/api/v1/scan/url", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          target: cleanTarget,
        }),
        signal: controller.signal,
      }).then(async (response) => {
        const contentType = response.headers.get("content-type") || "";
        const data = contentType.includes("application/json")
          ? await response.json()
          : await response.text();

        if (!response.ok) {
          const detail =
            typeof data === "object" && data?.detail
              ? data.detail
              : typeof data === "string" && data
                ? data
                : "The scan request failed.";

          throw new Error(detail);
        }

        return data;
      });

      // Keep the visual scan sequence, but never wait for history here.
      const [data] = await Promise.all([
        scanRequest,
        minimumAnimationTime,
      ]);

      setScanStage(SCAN_STAGES.length - 1);
      setScanProgress(100);
      setScanResult(data);

      // Clear the visible URL field after a completed scan.
      setTarget("");

      // The scan endpoint has already committed the record to PostgreSQL
      // before returning. Show it immediately even if the separate history
      // GET request is slow or temporarily unavailable.
      addLocalHistoryRecord(data);

      // Stop the loading UI as soon as the real scan succeeds.
      setLoading(false);

      // Refresh from PostgreSQL in the background. If it fails, the local
      // record above remains visible instead of producing a false error.
      void loadHistory();
    } catch (err) {
      if (err.name === "AbortError") {
        setError(
          "The scan request timed out. Check that the FraudLens backend and threat-intelligence services are running."
        );
      } else {
        setError(
          err.message || "Could not connect to the FraudLens backend."
        );
      }
    } finally {
      clearTimeout(timeout);
      setLoading(false);
    }
  }

  async function openHistoryItem(id) {
    if (String(id).startsWith("local-")) {
      const localRecord = history.find((record) => record.id === id);
      if (localRecord) {
        setSelectedScan(localRecord);
      }
      return;
    }

    try {
      const response = await fetch(
        `/api/v1/history/${id}`
      );

      if (!response.ok) {
        throw new Error(
          "Unable to load scan details."
        );
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

  const riskClass = getRiskClass(
    scanResult?.risk_level
  );

  const selectedRiskClass = getRiskClass(
    selectedScan?.risk_level
  );

  const activeScanTarget =
    scanResult?.target || target;

  const urlParts = useMemo(
    () => parseTargetParts(activeScanTarget),
    [activeScanTarget]
  );

  const intelProviders =
    scanResult?.intelligence || [];

  const availableIntel = intelProviders.filter(
    (provider) => provider.available
  );

  const maliciousIntel = availableIntel.filter(
    (provider) => provider.malicious
  );

  const localSignals =
    scanResult?.findings?.length || 0;

  const confidenceValue = confidencePercent(
    scanResult?.risk_assessment?.confidence
  );

  const telemetry = [
    {
      label: "LOCAL SIGNALS",
      value: localSignals,
      suffix: "DETECTED",
      width: Math.min(100, localSignals * 20),
    },
    {
      label: "INTEL MATCHES",
      value: maliciousIntel.length,
      suffix: "MATCHED",
      width: Math.min(
        100,
        maliciousIntel.length * 25
      ),
    },
    {
      label: "THREAT SCORE",
      value: scanResult ? riskScore : 0,
      suffix: "/ 100",
      width: riskScore,
    },
    {
      label: "CONFIDENCE",
      value: confidenceValue,
      suffix:
        confidenceValue === null
          ? "NOT REPORTED"
          : "%",
      width: confidenceValue ?? 0,
    },
  ];

  return (
    <div className={`app-shell ${showIntro ? "intro-active" : "intro-complete"}`}>
      {showIntro && (
        <div className="boot-sequence" aria-hidden="true">
          <div className="boot-grid" />
          <div className="boot-scanline" />
          <div className="boot-core">
            <div className="boot-ring boot-ring-one" />
            <div className="boot-ring boot-ring-two" />
            <div className="boot-ring boot-ring-three" />
            <div className="boot-shield"><Shield size={42} /></div>
          </div>
          <div className="boot-brand">
            <strong>FRAUD<span>LENS</span><sup>AI</sup></strong>
            <small>THREAT INTELLIGENCE PLATFORM</small>
          </div>
          <div className="boot-status">
            <span /> SYSTEM INITIALIZING <b>FRAUDLENS-X</b>
          </div>
        </div>
      )}

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
          <div className="status-item status-api">
            <Activity size={15} />
            <span>API</span>
            <strong>ONLINE</strong>
          </div>

          <div className="status-divider" />

          <div className="status-item status-optional">
            <ScanLine size={15} />
            <span>ENGINE</span>
            <strong>READY</strong>
          </div>

          <div className="status-divider status-optional" />

          <div className="status-item status-optional">
            <Radio size={15} />
            <span>INTEL</span>
            <strong>CONNECTED</strong>
          </div>

          <div className="status-divider status-optional" />

          <div className="status-item status-optional">
            <Database size={15} />
            <span>DB</span>
            <strong>OPERATIONAL</strong>
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

              <span>
                THREAT INTELLIGENCE / URL ANALYSIS
              </span>

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
              FraudLens analyzes suspicious URLs using
              deterministic local indicators and external
              threat intelligence to identify malicious
              infrastructure before interaction.
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
                ? scanStage >= 5
                  ? "CORRELATING"
                  : "ANALYZING"
                : scanResult
                  ? "COMPLETE"
                  : "STANDBY"}
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
                  value={target.replace(/^https?:\/\//i, "")}
                  onChange={(event) => {
                    const value = event.target.value
                      .replace(/^https?:\/\//i, "")
                      .trimStart();

                    // Keep the protocol out of the visible input.
                    // Internally we still store a normalized HTTPS URL so the
                    // backend always receives a complete URL.
                    setTarget(value ? `https://${value}` : "");
                  }}
                  placeholder="example.com/..."
                  disabled={loading}
                  autoComplete="off"
                  spellCheck={false}
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
                    {SCAN_STAGES[scanStage] ||
                      "ANALYZING TARGET"}
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

                <div className="scan-rings">
                  <span />
                  <span />
                  <span />
                </div>

                <div className="scan-packets">
                  <i />
                  <i />
                  <i />
                  <i />
                  <i />
                </div>

                <div className="scan-hud">
                  <div className="scan-hud-left">
                    <div className="scan-hud-icon">
                      <Shield size={25} />
                    </div>

                    <div>
                      <span>
                        FRAUDLENS-X SECURITY ENGINE
                      </span>

                      <strong>
                        {SCAN_STAGES[scanStage]}
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
                  {SCAN_STAGES.slice(0, 7).map(
                    (stage, index) => (
                      <div
                        className={
                          index <= scanStage
                            ? "log-active"
                            : ""
                        }
                        key={stage}
                      >
                        <span>
                          [
                          {String(index + 1).padStart(
                            2,
                            "0"
                          )}
                          ]
                        </span>

                        {stage}

                        <b>
                          {index < scanStage
                            ? "OK"
                            : index === scanStage
                              ? "RUN"
                              : "WAIT"}
                        </b>
                      </div>
                    )
                  )}
                </div>

                <div className="scan-progress-wrapper">
                  <div className="scan-progress-meta">
                    <span>
                      SECURITY ANALYSIS
                    </span>

                    <strong>
                      {scanProgress}%
                    </strong>
                  </div>

                  <div className="scan-progress">
                    <span
                      style={{
                        width: `${scanProgress}%`,
                      }}
                    />
                  </div>
                </div>
              </div>
            )}
          </div>

          <div className="security-mode">
            <span>◉ PASSIVE ANALYSIS MODE</span>

            <small>
              FraudLens never opens or executes the target
              URL during analysis.
            </small>
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
          <section
            className={`results-section ${
              resultRevealed
                ? "result-revealed"
                : "result-entering"
            }`}
          >
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

                {formatRiskLevel(
                  scanResult.risk_level
                )}
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
                      <strong>{displayScore}</strong>
                      <span>/ 100</span>
                    </div>
                  </div>

                  <div className="score-information">
                    <span className="card-label">
                      SYSTEM VERDICT
                    </span>

                    <h4>
                      {formatVerdict(
                        scanResult.risk_assessment
                          ?.verdict
                      )}
                    </h4>

                    <p>
                      Confidence{" "}
                      <strong>
                        {formatRiskLevel(
                          scanResult.risk_assessment
                            ?.confidence
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
                          copyTarget(
                            scanResult.target
                          )
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
                        scanResult.risk_assessment
                          ?.verdict
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
                    {
                      scanResult.risk_assessment
                        ?.explanation
                    }
                  </p>
                </div>
              </div>
            </div>

            <div className="intel-overview-grid">
              <div className="panel live-signal-panel">
                <div className="panel-header">
                  <div className="panel-title">
                    <div className="panel-icon intel">
                      <Radio size={16} />
                    </div>

                    <div>
                      <h4>LIVE THREAT SIGNAL</h4>
                      <span>
                        Observed from returned scan data
                      </span>
                    </div>
                  </div>

                  <span className="signal-live-dot">
                    ● LIVE
                  </span>
                </div>

                <div className="signal-grid">
                  <div>
                    <span>SIGNALS DETECTED</span>
                    <strong>{localSignals}</strong>
                  </div>

                  <div>
                    <span>INTELLIGENCE SOURCES</span>
                    <strong>
                      {availableIntel.length}
                    </strong>
                  </div>

                  <div>
                    <span>LOCAL INDICATORS</span>
                    <strong>{localSignals}</strong>
                  </div>

                  <div>
                    <span>CONFIDENCE</span>
                    <strong>
                      {scanResult.risk_assessment
                        ?.confidence ||
                        "Not reported"}
                    </strong>
                  </div>
                </div>
              </div>

              <div className="panel url-dna-panel">
                <div className="panel-header">
                  <div className="panel-title">
                    <div className="panel-icon intel">
                      <Link2 size={16} />
                    </div>

                    <div>
                      <h4>URL DNA / FORENSICS</h4>
                      <span>
                        Structural decomposition of analyzed
                        target
                      </span>
                    </div>
                  </div>

                  <span className="panel-count">
                    {urlParts.length}
                  </span>
                </div>

                <div className="url-dna-grid">
                  {urlParts.map((part) => (
                    <div
                      className="dna-cell"
                      key={part.key}
                    >
                      <div>
                        <span>{part.key}</span>
                        <b>{part.status}</b>
                      </div>

                      <strong title={part.value}>
                        {part.value}
                      </strong>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="telemetry-panel panel">
              <div className="telemetry-header">
                <div>
                  <span className="card-label">
                    ANALYSIS TELEMETRY
                  </span>

                  <h4>
                    Signal Correlation Matrix
                  </h4>
                </div>

                <span>
                  DERIVED FROM RETURNED DATA
                </span>
              </div>

              <div className="telemetry-grid">
                {telemetry.map((item) => (
                  <div
                    className="telemetry-item"
                    key={item.label}
                  >
                    <div className="telemetry-meta">
                      <span>{item.label}</span>

                      <strong>
                        {item.value === null
                          ? "—"
                          : item.value}
                        {item.suffix === "%"
                          ? "%"
                          : ""}
                      </strong>
                    </div>

                    <div className="telemetry-track">
                      <span
                        style={{
                          width: `${item.width}%`,
                        }}
                      />
                    </div>

                    <small>
                      {item.suffix === "%"
                        ? "CONFIDENCE VALUE"
                        : item.suffix}
                    </small>
                  </div>
                ))}
              </div>
            </div>

            <div className="trace-toggle-wrap">
              <button
                type="button"
                className="trace-toggle"
                onClick={() =>
                  setTraceOpen((open) => !open)
                }
              >
                <Terminal size={15} />

                {traceOpen
                  ? "HIDE ANALYSIS TRACE"
                  : "VIEW ANALYSIS TRACE"}

                <span>
                  {traceOpen ? "−" : "+"}
                </span>
              </button>
            </div>

            {traceOpen && (
              <div className="analysis-trace panel">
                <div className="trace-header">
                  <div>
                    <span className="card-label">
                      THREAT REPLAY / ANALYSIS TRACE
                    </span>

                    <h4>Analysis Workflow</h4>
                  </div>

                  <span>
                    VISUAL WORKFLOW · NOT BACKEND TELEMETRY
                  </span>
                </div>

                <div className="trace-pipeline">
                  {[
                    "TARGET RECEIVED",
                    "URL NORMALIZATION",
                    "STRUCTURAL ANALYSIS",
                    "LOCAL RULE ENGINE",
                    "THREAT INTELLIGENCE",
                    "SIGNAL CORRELATION",
                    "RISK SCORING",
                    "FINAL VERDICT",
                  ].map((node, index) => (
                    <div
                      className={`trace-node ${
                        index <= traceStage
                          ? "active"
                          : ""
                      }`}
                      key={node}
                    >
                      <span className="trace-node-index">
                        {String(index + 1).padStart(
                          2,
                          "0"
                        )}
                      </span>

                      <strong>{node}</strong>
                    </div>
                  ))}
                </div>
              </div>
            )}

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
                          className={`finding finding-${index}`}
                          key={`${finding.rule}-${index}`}
                        >
                          <div className="finding-index">
                            {String(index + 1).padStart(
                              2,
                              "0"
                            )}
                          </div>

                          <div className="finding-icon">
                            {Number(finding.score) > 0 ? (
                              <AlertTriangle size={16} />
                            ) : (
                              <CheckCircle2 size={16} />
                            )}
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
                      (provider) =>
                        provider.available
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
              <History
                className={
                  historyLoading
                    ? "refresh-spinning"
                    : ""
                }
                size={14}
              />

              {historyLoading
                ? "REFRESHING DATABASE"
                : "REFRESH DATABASE"}
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
                  <strong>NO SCAN RECORDS</strong>

                  <span>
                    Completed URL assessments will appear
                    in this database.
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
                    className={`history-row ${
                      record.local ? "history-row-local" : ""
                    }`}
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
                      {formatRiskLevel(
                        record.confidence
                      )}
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

                <h3>Intelligence Record</h3>
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
                RECORDED
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
                  fraudlens://records/
                  {selectedScan.id}
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