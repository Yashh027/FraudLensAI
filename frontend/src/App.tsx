import { useCallback, useEffect, useMemo, useState } from "react";

import {
  AlertTriangle,
  Activity,
  BarChart3,
  CalendarDays,
  CheckCircle2,
  Clock3,
  Copy,
  Database,
  Download,
  Globe2,
  GitCompare,
  History,
  Link2,
  Radio,
  Search,
  ScanLine,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Wifi,
  SlidersHorizontal,
  X,
  XCircle,
  Zap,
  LogOut,
  User as UserIcon,
} from "lucide-react";

import "./App.css";
import { AuthProvider, useAuth } from "./AuthContext";
import { LoginScreen, RegisterScreen } from "./AuthScreens";

// Production API base URL — empty string in development (Vite proxy handles /api).
// In production builds set VITE_API_BASE_URL to the backend's public HTTPS URL.
const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/+$/, "");

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

function healthClass(status) {
  if (status === "healthy") return "health-ok";
  if (status === "degraded") return "health-degraded";
  if (status === "unhealthy") return "health-down";
  return "health-checking";
}

function healthLabel(status, healthyLabel = "ONLINE") {
  if (status === "healthy") return healthyLabel;
  if (status === "degraded") return "DEGRADED";
  if (status === "unhealthy") return "OFFLINE";
  return "CHECKING";
}

function formatUptime(seconds) {
  if (!Number.isFinite(Number(seconds))) return "—";
  const total = Math.max(0, Math.floor(Number(seconds)));
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m`;
  return `${total}s`;
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
  const { user, token, logout, isLoading: authLoading } = useAuth();
  const [authMode, setAuthMode] = useState<"login" | "register">("login");

  // Both components are always mounted to keep hooks in consistent order
  // We just control visibility via CSS or conditional rendering of content
  if (authLoading) {
    return (
      <div className="auth-loading-screen">
        <div className="auth-loading-spinner" />
        <p>Initializing FraudLens...</p>
      </div>
    );
  }

  if (!user || !token) {
    return (
      <>
        {authMode === "login" ? (
          <LoginScreen onSwitchToRegister={() => setAuthMode("register")} />
        ) : (
          <RegisterScreen onSwitchToLogin={() => setAuthMode("login")} />
        )}
      </>
    );
  }

  // User is authenticated - render dashboard
  // Use key to force remount when user changes, avoiding hook comparison issues
  return <DashboardApp key={user?.id || 'dashboard'} token={token} user={user} logout={logout} />;
}

function DashboardApp({ token, user, logout }: { token: string; user: any; logout: () => void }) {
  // All state and hooks for dashboard - only rendered when user is authenticated
  const [target, setTarget] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [scanTimestamp, setScanTimestamp] = useState(null);
  const [history, setHistory] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [historySearch, setHistorySearch] = useState("");
  const [historyRisk, setHistoryRisk] = useState("");
  const [historyStatus, setHistoryStatus] = useState("");
  const [historyStartDate, setHistoryStartDate] = useState("");
  const [historyEndDate, setHistoryEndDate] = useState("");
  const [compareLeft, setCompareLeft] = useState("");
  const [compareRight, setCompareRight] = useState("");
  const [comparison, setComparison] = useState(null);
  const [comparisonCandidates, setComparisonCandidates] = useState([]);
  const [comparisonLoading, setComparisonLoading] = useState(false);
  const [dashboardStats, setDashboardStats] = useState(null);
  const [dashboardLoading, setDashboardLoading] = useState(true);
  const [systemHealth, setSystemHealth] = useState(null);
  const [historyError, setHistoryError] = useState("");
  const [dashboardError, setDashboardError] = useState("");
  const [loading, setLoading] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const [showIntro, setShowIntro] = useState(true);
  const [scanStage, setScanStage] = useState(0);
  const [scanProgress, setScanProgress] = useState(0);
  const [displayScore, setDisplayScore] = useState(0);
  const [traceOpen, setTraceOpen] = useState(false);
  const [traceStage, setTraceStage] = useState(-1);
  const [resultRevealed, setResultRevealed] = useState(false);

  const authHeaders = useMemo(() => {
    if (!token) return {};
    return { Authorization: `Bearer ${token}` };
  }, [token]);

  const loadHistory = useCallback(async () => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    try {
      setHistoryLoading(true);
      const params = new URLSearchParams({ limit: "100" });
      if (historySearch.trim()) params.set("search", historySearch.trim());
      if (historyRisk) params.set("risk_level", historyRisk);
      if (historyStatus) params.set("status", historyStatus);
      if (historyStartDate) params.set("start_date", historyStartDate);
      if (historyEndDate) params.set("end_date", historyEndDate);

      const response = await fetch(`${API_BASE}/api/v1/history?${params.toString()}`,{
        method: "GET", signal: controller.signal, cache: "no-store",
        headers: authHeaders,
      });
      if (!response.ok) throw new Error(`History API returned ${response.status}.`);
      const data = await response.json();
      const records = Array.isArray(data) ? data : Array.isArray(data?.items) ? data.items : null;
      if (records === null) throw new Error("History API returned an invalid response.");
      setHistory(records);
      setHistoryError("");
      return true;
    } catch (err) {
      console.warn("Scan history unavailable:", err);
      setHistoryError(
        err.name === "AbortError"
          ? "History request timed out. Check backend health and try again."
          : "Scan history is temporarily unavailable. Your existing records were not deleted."
      );
      return false;
    } finally {
      clearTimeout(timeout);
      setHistoryLoading(false);
    }
  }, [historySearch, historyRisk, historyStatus, historyStartDate, historyEndDate, authHeaders]);

  const loadComparisonCandidates = useCallback(async () => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    try {
      const response = await fetch(`${API_BASE}/api/v1/history?limit=200&offset=0`,{
        method: "GET",
        cache: "no-store",
        signal: controller.signal,
        headers: authHeaders,
      });
      if (!response.ok) throw new Error(`Comparison history API returned ${response.status}.`);
      const data = await response.json();
      const records = Array.isArray(data)
        ? data
        : Array.isArray(data?.items)
          ? data.items
          : [];
      setComparisonCandidates(
        records.filter((record) => !record.local && record.id != null)
      );
    } catch (err) {
      console.warn("Comparison candidates unavailable:", err);
      setComparisonCandidates([]);
    } finally {
      clearTimeout(timeout);
    }
  }, [authHeaders]);

  const loadDashboardStats = useCallback(async () => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    try {
      setDashboardLoading(true);
      const response = await fetch(`${API_BASE}/api/v1/history/stats/overview`,{
        cache: "no-store",
        signal: controller.signal,
        headers: authHeaders,
      });
      if (!response.ok) throw new Error(`Dashboard API returned ${response.status}.`);
      setDashboardStats(await response.json());
      setDashboardError("");
    } catch (err) {
      console.warn("Dashboard statistics unavailable:", err);
      setDashboardStats(null);
      setDashboardError("Live dashboard data is temporarily unavailable.");
    } finally {
      clearTimeout(timeout);
      setDashboardLoading(false);
    }
  }, [authHeaders]);

  const loadSystemHealth = useCallback(async () => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    try {
      const response = await fetch(`${API_BASE}/health`,{
        cache: "no-store",
        signal: controller.signal,
        headers: authHeaders,
      });
      const data = await response.json().catch(() => null);
      if (!response.ok || !data?.components) {
        throw new Error(data?.detail || `Health API returned ${response.status}.`);
      }
      setSystemHealth(data);
      return data;
    } catch (err) {
      console.warn("System health unavailable:", err);
      setSystemHealth({
        status: "unhealthy",
        uptime_seconds: null,
        components: {
          api: { status: "unhealthy", message: "Backend API is unreachable." },
          engine: { status: "unhealthy", message: "Scan engine status cannot be verified." },
          database: { status: "unhealthy", message: "Database status cannot be verified." },
          intelligence: { status: "degraded", message: "Provider status cannot be verified." },
        },
      });
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }, [authHeaders]);

  function scrollToTop() {
    window.scrollTo({
      top: 0,
      left: 0,
      behavior: "smooth",
    });
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
    loadComparisonCandidates();
    loadDashboardStats();
    loadSystemHealth();

    const healthInterval = setInterval(() => {
      void loadSystemHealth();
    }, 15000);

    return () => {
      clearTimeout(introTimer);
      clearTimeout(forceTop);
      clearInterval(healthInterval);
    };
  }, []);

  useEffect(() => {
    if (!showIntro) {
      loadHistory();
      loadComparisonCandidates();
    }
    // Filters drive the visible history query. Comparison candidates remain
    // unfiltered so every persisted scan can be selected for comparison.
  }, [historySearch, historyRisk, historyStatus, historyStartDate, historyEndDate]);

  useEffect(() => {
    // Keep the operations dashboard current while the app is open.
    const refreshInterval = setInterval(() => {
      void loadDashboardStats();
      void loadComparisonCandidates();
    }, 15000);

    return () => clearInterval(refreshInterval);
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

  async function exportSecurityReport(scan, historyId = null) {
    if (!scan && !historyId) {
      setError("No scan report is available to export.");
      return;
    }

    try {
      const response = historyId
        ? await fetch(`${API_BASE}/api/v1/history/${historyId}/report.pdf`,{ cache: "no-store", headers: authHeaders })
        : await fetch(`${API_BASE}/api/v1/scan/report.pdf`,{
            method: "POST",
            headers: { ...authHeaders, "Content-Type": "application/json", Accept: "application/pdf" },
            body: JSON.stringify(scan),
          });

      if (!response.ok) {
        const contentType = response.headers.get("content-type") || "";
        let detail = `Report export failed (${response.status}).`;
        if (contentType.includes("application/json")) {
          const payload = await response.json();
          detail = payload?.detail || detail;
        }
        throw new Error(detail);
      }

      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = historyId
        ? `FraudLens_Security_Report_${historyId}.pdf`
        : "FraudLens_Security_Report.pdf";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Security report export failed:", err);
      setError(err.message || "Unable to export the security report.");
    }
  }

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
    const timeout = setTimeout(() => controller.abort(), 75000);

    const minimumAnimationTime = new Promise((resolve) =>
      setTimeout(resolve, 5000)
    );

    try {
      const scanRequest = fetch(`${API_BASE}/api/v1/scan/url`,{
        method: "POST",
        headers: { ...authHeaders, "Content-Type": "application/json" },
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
      setScanTimestamp(new Date().toISOString());

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
      void loadComparisonCandidates();
      void loadDashboardStats();
      void loadSystemHealth();
    } catch (err) {
      if (err.name === "AbortError") {
        setError(
          "The scan timed out before all analysis services returned. No target page was opened or executed; try the scan again or check system health."
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
        `${API_BASE}/api/v1/history/${id}`,
        { headers: authHeaders }
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

  async function compareSelectedScans() {
    if (!compareLeft || !compareRight) {
      setError("Select two scans to compare.");
      return;
    }
    if (compareLeft === compareRight) {
      setError("Choose two different scans to compare.");
      return;
    }

    setComparisonLoading(true);
    setError("");

    try {
      const params = new URLSearchParams({
        left_id: String(compareLeft),
        right_id: String(compareRight),
      });
      const response = await fetch(`${API_BASE}/api/v1/history/compare?${params.toString()}`, {
        method: "GET",
        cache: "no-store",
        headers: { ...authHeaders, Accept: "application/json" },
      });

      const contentType = response.headers.get("content-type") || "";
      const data = contentType.includes("application/json")
        ? await response.json()
        : null;

      if (!response.ok) {
        throw new Error(
          data?.detail || `Comparison API returned ${response.status}.`
        );
      }

      if (!data?.left || !data?.right || !data?.summary) {
        throw new Error("Comparison API returned an incomplete comparison.");
      }

      setComparison(data);

      // The result is rendered below the history table. Bring it into view
      // so a successful comparison never looks like the button did nothing.
      requestAnimationFrame(() => {
        document.querySelector(".comparison-panel")?.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
      });
    } catch (err) {
      console.error("Scan comparison failed:", err);
      setComparison(null);
      setError(err.message || "Unable to compare scans.");
    } finally {
      setComparisonLoading(false);
    }
  }


  function refreshPhase3Data() {
    void loadHistory();
    void loadComparisonCandidates();
    void loadDashboardStats();
    void loadSystemHealth();
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

  const urlParts = useMemo(() => {
    if (scanResult?.url_components?.length) {
      return scanResult.url_components;
    }
    return parseTargetParts(activeScanTarget);
  }, [scanResult, activeScanTarget]);

  const domainInfo = scanResult?.domain_info || {};
  const registration = domainInfo.registration || {};
  const dns = domainInfo.dns || {};
  const infrastructure = domainInfo.infrastructure || {};
  const infrastructureSignals = domainInfo.risk_signals || [];
  const activeLocalFindings = scanResult?.findings || [];
  const activeIntel = scanResult?.intelligence || [];

  function humanizeRule(rule) {
    return String(rule || "finding")
      .replace(/_/g, " ")
      .replace(/\b\w/g, (char) => char.toUpperCase());
  }

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

      {/* Skip navigation for accessibility */}
      <a href="#scanner-input" className="skip-link">
        Skip to scanner
      </a>

      {/* ================= BACKGROUND SYSTEM ================= */}

      <div className="ambient-grid" aria-hidden="true" />
      <div className="ambient-glow glow-one" aria-hidden="true" />
      <div className="ambient-glow glow-two" aria-hidden="true" />
      <div className="scanlines" aria-hidden="true" />

      {/* ================= HEADER ================= */}

      <header className="topbar">
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flex: 1 }}>
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
        </div>

        <div className="system-status">
          <div className={`status-item status-api ${healthClass(systemHealth?.components?.api?.status)}`}>
            <Activity size={15} />
            <span>API</span>
            <strong>{healthLabel(systemHealth?.components?.api?.status)}</strong>
          </div>

          <div className="status-divider" />

          <div className={`status-item status-optional ${healthClass(systemHealth?.components?.engine?.status)}`}>
            <ScanLine size={15} />
            <span>ENGINE</span>
            <strong>{healthLabel(systemHealth?.components?.engine?.status, "READY")}</strong>
          </div>

          <div className="status-divider status-optional" />

          <div className={`status-item status-optional ${healthClass(systemHealth?.components?.intelligence?.status)}`}>
            <Radio size={15} />
            <span>INTEL</span>
            <strong>{healthLabel(systemHealth?.components?.intelligence?.status, "CONNECTED")}</strong>
          </div>

          <div className="status-divider status-optional" />

          <div className={`status-item status-optional ${healthClass(systemHealth?.components?.database?.status)}`}>
            <Database size={15} />
            <span>DB</span>
            <strong>{healthLabel(systemHealth?.components?.database?.status, "OPERATIONAL")}</strong>
          </div>

          <div className="status-divider" />

          <div className="status-item">
            <Server size={15} />
            <span>UPTIME</span>
            <strong>{formatUptime(systemHealth?.uptime_seconds)}</strong>
          </div>

          <div className="status-divider" />

          <div className="status-item status-user">
            <UserIcon size={15} />
            <span title={user.email} style={{ maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{user.email}</span>
            <button
              className="logout-btn"
              onClick={logout}
              title="Sign out"
            >
              <LogOut size={14} />
            </button>
          </div>
        </div>
      </header>

      <main className="dashboard" id="main-content" role="main">
        {/* ================= HERO ================= */}

        <section className="hero" aria-label="Introduction">
          <div className="hero-content">
            <div className="hero-kicker">
              <span className="kicker-line" />

              <span>
                THREAT INTELLIGENCE / URL ANALYSIS
              </span>

              <span className={`kicker-status ${systemHealth?.status === "degraded" ? "health-kicker-degraded" : systemHealth?.status === "unhealthy" ? "health-kicker-down" : ""}`}>
                <span />
                {systemHealth ? (systemHealth.status === "healthy" ? "SYSTEM READY" : systemHealth.status === "degraded" ? "SYSTEM DEGRADED" : "SYSTEM OFFLINE") : "SYSTEM CHECKING"}
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

        {/* ================= DASHBOARD ================= */}
        <section className="phase3-dashboard panel">
          <div className="section-heading dashboard-heading">
            <div>
              <span className="eyebrow">00 / OPERATIONS DASHBOARD</span>
              <h3>Threat Activity Overview</h3>
            </div>
            <span className={`dashboard-live ${dashboardError ? "dashboard-live-error" : ""}`}>
              <span /> {dashboardError ? "DATABASE UNAVAILABLE" : "REAL DATA / POSTGRESQL"}
              {dashboardStats?.generated_at && !dashboardError && (
                <small> · UPDATED {new Date(dashboardStats.generated_at).toLocaleTimeString()}</small>
              )}
            </span>
          </div>

          <div className="dashboard-stat-grid">
            {[
              ["TOTAL SCANS", dashboardStats ? dashboardStats.total_scans : "—", "All recorded assessments", "total"],
              ["SAFE", dashboardStats ? dashboardStats.safe_scans : "—", "Score below 25", "safe"],
              ["SUSPICIOUS", dashboardStats ? dashboardStats.suspicious_scans : "—", "Score 25–49", "medium"],
              ["HIGH RISK", dashboardStats ? dashboardStats.high_risk_scans : "—", "Score 50–69", "high"],
              ["CRITICAL", dashboardStats ? dashboardStats.critical_scans : "—", "Score 70–100", "critical"],
              ["AVG RISK", dashboardStats ? dashboardStats.average_risk_score : "—", "Across recorded scans", "avg"],
            ].map(([label, value, note, tone]) => (
              <div className={`dashboard-stat ${tone}`} key={label}>
                <span>{label}</span>
                <strong>{dashboardLoading ? "—" : value}</strong>
                <small>{note}</small>
              </div>
            ))}
          </div>

          {dashboardError && (
            <div className="dashboard-error-banner"><XCircle size={14} /> {dashboardError} The dashboard will retry automatically.</div>
          )}

          <div className="dashboard-lower-grid">
            <div className="dashboard-distribution">
              <div className="dashboard-subhead"><BarChart3 size={15} /><span>RISK DISTRIBUTION</span></div>
              {[["low", "Safe"], ["medium", "Suspicious"], ["high", "High Risk"], ["critical", "Critical"]].map(([key, label]) => {
                const value = dashboardError ? null : (dashboardStats?.risk_distribution?.[key] ?? 0);
                const total = dashboardStats?.total_scans || 1;
                return (
                  <div className="distribution-row" key={key}>
                    <span>{label}</span><div><i style={{ width: `${value == null ? 0 : Math.min(100, (value / total) * 100)}%` }} /></div><strong>{value == null ? "—" : value}</strong>
                  </div>
                );
              })}
            </div>
            <div className="dashboard-threats">
              <div className="dashboard-subhead"><Radio size={15} /><span>THREAT INTELLIGENCE ACTIVITY</span></div>
              {dashboardError ? (
                <div className="dashboard-no-data">Threat activity cannot be queried while the database is unavailable.</div>
              ) : Object.entries(dashboardStats?.threat_statistics || {}).length ? Object.entries(dashboardStats.threat_statistics).map(([provider, stats]) => (
                <div className="threat-stat-row" key={provider}>
                  <strong>{provider}</strong><span>{stats.checks} checks</span><b>{stats.malicious_matches} malicious matches</b>
                </div>
              )) : <div className="dashboard-no-data">No provider history recorded yet.</div>}
            </div>
            <div className="dashboard-recent">
              <div className="dashboard-subhead"><Clock3 size={15} /><span>RECENT SCANS</span></div>
              {dashboardError ? (
                <div className="dashboard-no-data">Recent scans cannot be queried while the database is unavailable.</div>
              ) : (dashboardStats?.recent_scans || []).length ? dashboardStats.recent_scans.slice(0, 5).map((record) => (
                <button type="button" className="recent-scan-row" key={record.id} onClick={() => openHistoryItem(record.id)}>
                  <span>{record.target}</span><b className={getRiskClass(record.risk_level)}>{record.risk_score}</b><small>{new Date(record.created_at).toLocaleString()}</small>
                </button>
              )) : <div className="dashboard-no-data">No scans recorded yet.</div>}
            </div>
          </div>
        </section>

        {/* ================= SCANNER ================= */}

        <section
          className={`scanner-card ${
            loading ? "is-scanning" : ""
          }`}
          aria-label="URL security scanner"
          aria-busy={loading}
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
              <div className="input-wrapper" id="scanner-input">
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
                aria-label={loading ? SCAN_STAGES[scanStage] || "Scanning" : "Initiate URL scan"}
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
            <div className="error-banner" role="alert">
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
            aria-label="Scan results"
            aria-live="polite"
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

            <div className={`result-grid`}>
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

                  <div className="assessment-actions">
                    <div className="analyzed-status">
                      <span />
                      ANALYSIS COMPLETE
                    </div>
                    <button
                      type="button"
                      className="report-export-button"
                      onClick={() => exportSecurityReport({ ...scanResult, scan_timestamp: scanTimestamp })}
                      title="Export Security Report"
                    >
                      <Download size={14} />
                      EXPORT PDF
                    </button>
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

            <div className="explainability-panel panel">
              <div className="panel-header">
                <div className="panel-title">
                  <div className={`panel-icon ${riskClass === "low" ? "safe" : "warning"}`}>
                    <Shield size={16} />
                  </div>
                  <div>
                    <h4>Why is this dangerous?</h4>
                    <span>Evidence-backed explanation of the final assessment</span>
                  </div>
                </div>
                <span className={`explain-verdict ${riskClass}`}>
                  {formatVerdict(scanResult.risk_assessment?.verdict)}
                </span>
              </div>

              <div className="explain-grid">
                <div className="explain-column">
                  <span className="explain-kicker">01 / LOCAL SIGNALS</span>
                  <strong>{activeLocalFindings.length ? `${activeLocalFindings.length} detected` : "None detected"}</strong>
                  {activeLocalFindings.length ? (
                    <ul>
                      {activeLocalFindings.map((finding) => (
                        <li key={finding.rule}>
                          <span>{humanizeRule(finding.rule)}</span>
                          <b>+{finding.score}</b>
                          <small>{finding.description}</small>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p>No significant URL-level characteristics increased local risk.</p>
                  )}
                </div>

                <div className="explain-column">
                  <span className="explain-kicker">02 / THREAT INTELLIGENCE</span>
                  <strong>{availableIntel.length ? `${availableIntel.length} source${availableIntel.length === 1 ? "" : "s"} available` : "No sources available"}</strong>
                  {availableIntel.length ? (
                    <ul>
                      {activeIntel.map((provider) => (
                        <li key={provider.provider}>
                          <span>{provider.provider}</span>
                          <b>{provider.available ? (provider.malicious ? "MALICIOUS" : `${provider.score ?? 0}/100`) : "UNAVAILABLE"}</b>
                          <small>{provider.details}</small>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p>External intelligence was unavailable, so the final assessment relies on local evidence only.</p>
                  )}
                </div>

                <div className="explain-column final-column">
                  <span className="explain-kicker">03 / FINAL ASSESSMENT</span>
                  <strong>{riskScore}/100 · {formatRiskLevel(scanResult.risk_level)}</strong>
                  <p>{scanResult.risk_assessment?.explanation || "No explanation was returned by the assessment engine."}</p>
                  <div className="recommendation-box">
                    <span>RECOMMENDATION</span>
                    <p>{scanResult.recommendation}</p>
                  </div>
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
                    <span>INFRA SIGNALS</span>
                    <strong>{infrastructureSignals.filter((signal) => Number(signal.score) > 0).length}</strong>
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
                      className={`dna-cell ${part.suspicious ? "dna-cell-suspicious" : ""}`}
                      key={part.key}
                    >
                      <div>
                        <span>{part.key}</span>
                        <b>{part.status}</b>
                      </div>

                      <strong title={part.value}>
                        {part.value}
                      </strong>

                      {part.suspicious && part.reason && (
                        <small className="dna-warning">{part.reason}</small>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="domain-intel-grid">
              <div className="panel domain-intelligence-panel">
                <div className="panel-header">
                  <div className="panel-title">
                    <div className="panel-icon intel"><Globe2 size={16} /></div>
                    <div>
                      <h4>DOMAIN INTELLIGENCE</h4>
                      <span>Passive registration and infrastructure context</span>
                    </div>
                  </div>
                  <span className="panel-count">{domainInfo.lookup_status === "complete" ? "LIVE" : "PARTIAL"}</span>
                </div>
                <div className="domain-facts">
                  <div><span>REGISTERED DOMAIN</span><strong>{domainInfo.domain || "—"}</strong></div>
                  <div><span>SUBDOMAIN</span><strong>{domainInfo.subdomain || "NONE"}</strong></div>
                  <div><span>TLD</span><strong>{domainInfo.tld ? `.${domainInfo.tld}` : "—"}</strong></div>
                  <div><span>REGISTRAR</span><strong>{registration.registrar || "Not available"}</strong></div>
                  <div><span>DOMAIN AGE</span><strong>{registration.age_days != null ? `${registration.age_days} days` : "Not available"}</strong></div>
                  <div><span>IP ADDRESS</span><strong>{(infrastructure.ips || []).join(", ") || "Not resolved"}</strong></div>
                  <div><span>COUNTRY / LOCATION</span><strong>{[infrastructure.city, infrastructure.region, infrastructure.country].filter(Boolean).join(", ") || "Not available"}</strong></div>
                  <div><span>ASN / NETWORK</span><strong>{infrastructure.asn ? `AS${infrastructure.asn}${infrastructure.org ? ` · ${infrastructure.org}` : ""}` : "Not available"}</strong></div>
                  <div><span>ISP / HOSTING</span><strong>{infrastructure.isp || infrastructure.network || "Not available"}</strong></div>
                  <div><span>NAMESERVERS</span><strong>{(registration.nameservers || []).join(", ") || "Not available"}</strong></div>
                </div>
                {infrastructureSignals.length > 0 && (
                  <div className="infra-signal-list">
                    {infrastructureSignals.map((signal) => (
                      <div key={signal.rule} className={`infra-signal ${Number(signal.score) > 0 ? "active" : "neutral"}`}>
                        <span>{humanizeRule(signal.rule)}</span>
                        <b>{Number(signal.score) > 0 ? `+${signal.score}` : "INFO"}</b>
                        <small>{signal.description}</small>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="panel dns-panel">
                <div className="panel-header">
                  <div className="panel-title">
                    <div className="panel-icon intel"><Server size={16} /></div>
                    <div>
                      <h4>DNS / INFRASTRUCTURE</h4>
                      <span>Passive DNS records and resolved infrastructure</span>
                    </div>
                  </div>
                  <span className="panel-count">{Object.values(dns).reduce((count, records) => count + (Array.isArray(records) ? records.length : 0), 0)}</span>
                </div>
                <div className="dns-record-grid">
                  {["A", "AAAA", "MX", "NS"].map((type) => (
                    <div className="dns-record" key={type}>
                      <span>{type}</span>
                      <div>
                        {(dns[type] || []).length ? (dns[type] || []).map((record) => <code key={record}>{record}</code>) : <small>NO RECORD RETURNED</small>}
                      </div>
                    </div>
                  ))}
                </div>
                <div className="data-source-note">
                  <Wifi size={13} />
                  <span>{(domainInfo.data_sources || []).join(" · ") || "Passive enrichment unavailable"}</span>
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

        <section className="history-section" aria-label="Scan history">
          <div className="section-heading">
            <div>
              <span className="eyebrow">
                03 / INTELLIGENCE DATABASE
              </span>

              <h3>Scan History</h3>
              <span className="history-result-count">{historyError ? "DATABASE UNAVAILABLE" : `${history.length} records shown`}</span>
            </div>

            <button
              className="refresh-button"
              onClick={refreshPhase3Data}
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

          <div className="history-controls panel">
            <div className="history-search"><Search size={15} /><input value={historySearch} onChange={(event) => setHistorySearch(event.target.value)} placeholder="Search target URL..." /></div>
            <select value={historyRisk} onChange={(event) => setHistoryRisk(event.target.value)} aria-label="Filter by risk level">
              <option value="">All risk levels</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option>
            </select>
            <select value={historyStatus} onChange={(event) => setHistoryStatus(event.target.value)} aria-label="Filter by status">
              <option value="">All statuses</option><option value="completed">Completed</option><option value="partial">Partial</option><option value="failed">Failed</option>
            </select>
            <label><CalendarDays size={14} /><input type="date" value={historyStartDate} onChange={(event) => setHistoryStartDate(event.target.value)} /></label>
            <label><CalendarDays size={14} /><input type="date" value={historyEndDate} onChange={(event) => setHistoryEndDate(event.target.value)} /></label>
            <button type="button" className="clear-filter-button" onClick={() => { setHistorySearch(""); setHistoryRisk(""); setHistoryStatus(""); setHistoryStartDate(""); setHistoryEndDate(""); }}><SlidersHorizontal size={14} /> RESET</button>
          </div>

          <div className="history-compare-bar panel">
            <div><GitCompare size={16} /><div><strong>Compare two scans</strong><span>{comparisonCandidates.length ? `${comparisonCandidates.length} historical scans available. Choose two to see risk and signal changes.` : "No persisted scans are available yet."}</span></div></div>
            <select value={compareLeft} onChange={(event) => setCompareLeft(event.target.value)} aria-label="First scan">
              <option value="">First scan...</option>{comparisonCandidates.map((record) => <option value={record.id} key={`left-${record.id}`}>{record.risk_score}/100 · {record.target}{record.has_report ? "" : " · SUMMARY ONLY"}</option>)}
            </select>
            <select value={compareRight} onChange={(event) => setCompareRight(event.target.value)} aria-label="Second scan">
              <option value="">Second scan...</option>{comparisonCandidates.map((record) => <option value={record.id} key={`right-${record.id}`}>{record.risk_score}/100 · {record.target}{record.has_report ? "" : " · SUMMARY ONLY"}</option>)}
            </select>
            <button type="button" className="compare-button" onClick={compareSelectedScans} disabled={comparisonLoading}>{comparisonLoading ? "COMPARING..." : "COMPARE"}</button>
          </div>

          {historyError && !historyLoading && (
            <div className="history-error-banner"><XCircle size={15} /> {historyError}</div>
          )}

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
                  <span>Status</span>
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
                      {formatRiskLevel(record.confidence)}
                    </span>

                    <span className="history-status">
                      {formatRiskLevel(record.status || "completed")}
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

        {comparison && (
          <section className="comparison-panel panel">
            <div className="comparison-header">
              <div><span className="eyebrow">04 / INVESTIGATION</span><h3>Scan Comparison</h3></div>
              <button type="button" className="close-button" onClick={() => setComparison(null)}><X size={17} /></button>
            </div>
            <div className="comparison-targets">
              {[comparison.left, comparison.right].map((item, index) => <div className="comparison-target" key={item.id}><span>{index === 0 ? "BASELINE" : "LATEST"}</span><strong>{item.target}</strong><b className={getRiskClass(item.risk_level)}>{item.risk_score}/100 · {formatRiskLevel(item.risk_level)}</b><small>{formatVerdict(item.verdict)} · {formatRiskLevel(item.confidence)}</small></div>)}
            </div>
            <div className={`comparison-delta ${comparison.summary.risk_score_delta > 0 ? "increased" : comparison.summary.risk_score_delta < 0 ? "decreased" : "unchanged"}`}>
              <Activity size={16} /> Risk changed by <strong>{comparison.summary.risk_score_delta > 0 ? "+" : ""}{comparison.summary.risk_score_delta}</strong> points {comparison.summary.risk_score_delta > 0 ? "up" : comparison.summary.risk_score_delta < 0 ? "down" : "with no score change"}.
            </div>
            <div className="comparison-grid">
              <div><h4>LOCAL SIGNAL CHANGES</h4>{comparison.local_signal_changes.length ? comparison.local_signal_changes.map((change) => <div className={`comparison-change ${change.score_delta > 0 ? "up" : "down"}`} key={change.rule}><strong>{humanizeRule(change.rule)}</strong><span>{change.score_delta > 0 ? "+" : ""}{change.score_delta} pts</span><small>{change.change}</small></div>) : <p>No local signal changes.</p>}</div>
              <div><h4>INTELLIGENCE CHANGES</h4>{comparison.intelligence_changes.length ? comparison.intelligence_changes.map((change) => <div className="comparison-change" key={change.provider}><strong>{change.provider}</strong><span>{change.score_delta == null ? "Status changed" : `${change.score_delta > 0 ? "+" : ""}${change.score_delta} pts`}</span><small>{change.change}</small></div>) : <p>No intelligence changes.</p>}</div>
            </div>
          </section>
        )}
      </main>

      {/* ================= HISTORY MODAL ================= */}

      {selectedScan && (
        <div
          className="modal-backdrop"
          onClick={() => setSelectedScan(null)}
          onKeyDown={(event) => {
            if (event.key === "Escape") setSelectedScan(null);
          }}
          tabIndex={-1}
          ref={(el) => {
            if (el) el.focus();
          }}
        >
          <div
            className={`history-modal ${selectedRiskClass}`}
            onClick={(event) =>
              event.stopPropagation()
            }
            role="dialog"
            aria-modal="true"
            aria-label={`Scan details for ${selectedScan.target}`}
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

              {!String(selectedScan.id).startsWith("local-") && (
                <button
                  type="button"
                  className="report-export-button modal-report-export"
                  onClick={() => exportSecurityReport(selectedScan, selectedScan.id)}
                  title="Export Security Report"
                >
                  <Download size={14} />
                  EXPORT PDF
                </button>
              )}
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

            {selectedScan.report && (
              <div className="historical-report">
                <div className="historical-report-header"><div><span className="card-label">COMPLETE HISTORICAL REPORT</span><h4>Recorded Assessment</h4></div><span>{selectedScan.report.findings?.length || 0} local signals · {selectedScan.report.intelligence?.length || 0} providers</span></div>
                <div className="historical-report-grid">
                  <div><span>LOCAL SIGNALS</span><strong>{selectedScan.report.findings?.length || 0}</strong></div>
                  <div><span>INTEL MATCHES</span><strong>{(selectedScan.report.intelligence || []).filter((item) => item.malicious).length}</strong></div>
                  <div><span>DOMAIN LOOKUP</span><strong>{selectedScan.report.domain_info?.lookup_status || "Not recorded"}</strong></div>
                  <div><span>RECOMMENDATION</span><strong>{selectedScan.report.recommendation || "Not recorded"}</strong></div>
                </div>
                {selectedScan.report.risk_assessment?.explanation && <p className="historical-explanation">{selectedScan.report.risk_assessment.explanation}</p>}
                <div className="historical-detail-grid">
                  <div><h5>LOCAL FINDINGS</h5>{(selectedScan.report.findings || []).length ? selectedScan.report.findings.map((finding) => <div className="historical-detail-row" key={`${finding.rule}-${finding.score}`}><strong>{humanizeRule(finding.rule)}</strong><span>+{finding.score}</span><small>{finding.description}</small></div>) : <p>No local findings.</p>}</div>
                  <div><h5>THREAT INTELLIGENCE</h5>{(selectedScan.report.intelligence || []).length ? selectedScan.report.intelligence.map((provider) => <div className="historical-detail-row" key={provider.provider}><strong>{provider.provider}</strong><span>{provider.score ?? "—"}</span><small>{provider.available ? (provider.malicious ? "Malicious result" : "No malicious result") : "Unavailable"}</small></div>) : <p>No provider data.</p>}</div>
                  <div><h5>URL COMPONENTS</h5>{(selectedScan.report.url_components || []).map((part) => <div className={`historical-detail-row ${part.suspicious ? "suspicious" : ""}`} key={part.key}><strong>{part.key}</strong><span>{part.suspicious ? "FLAGGED" : part.status}</span><small>{part.value}{part.reason ? ` · ${part.reason}` : ""}</small></div>)}</div>
                  <div><h5>DOMAIN / INFRASTRUCTURE</h5><div className="historical-infra-lines"><span>Domain <b>{selectedScan.report.domain_info?.domain || "—"}</b></span><span>Registrar <b>{selectedScan.report.domain_info?.registration?.registrar || "—"}</b></span><span>IPs <b>{(selectedScan.report.domain_info?.infrastructure?.ips || []).join(", ") || "—"}</b></span><span>ASN <b>{selectedScan.report.domain_info?.infrastructure?.asn ? `AS${selectedScan.report.domain_info.infrastructure.asn}` : "—"}</b></span></div></div>
                </div>
              </div>
            )}

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