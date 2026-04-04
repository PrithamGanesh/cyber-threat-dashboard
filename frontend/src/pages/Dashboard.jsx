import { useState, useEffect, useCallback } from "react";
import { AlertTable } from "../components/AlertTable";
import { LiveFeed } from "../components/LiveFeed";
import { MapView } from "../components/MapView";
import { api } from "../services/api";

const SEVERITY_CONFIG = {
  critical: { color: "#ff2d55", label: "Critical" },
  high:     { color: "#ff9f0a", label: "High"     },
  medium:   { color: "#ffd60a", label: "Medium"   },
  low:      { color: "#30d158", label: "Low"      },
};

function StatCard({ label, value, color, sub }) {
  return (
    <div className="stat-card" style={{ "--accent": color }}>
      <div className="stat-value" style={{ color }}>{value ?? "—"}</div>
      <div className="stat-label">{label}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

export function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [health, setHealth] = useState(null);
  const [selected, setSelected] = useState(null);
  const [severityFilter, setSeverityFilter] = useState("");
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [alertData, statsData, healthData] = await Promise.all([
        api.getAlerts({ limit: 200, severity: severityFilter || undefined }),
        api.getStats(),
        api.getHealth(),
      ]);
      setAlerts(alertData);
      setStats(statsData);
      setHealth(healthData);
    } catch (e) {
      console.error("Fetch error:", e);
    } finally {
      setLoading(false);
    }
  }, [severityFilter]);

  // Initial load + poll every 30s
  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30_000);
    return () => clearInterval(interval);
  }, [fetchData]);

  // SSE live stream
  useEffect(() => {
    const unsub = api.subscribeToAlerts((alert) => {
      setLiveAlerts((prev) => [...prev.slice(-49), alert]);
      setAlerts((prev) => [alert, ...prev.slice(0, 199)]);
      setStats((prev) =>
        prev
          ? {
              ...prev,
              total: prev.total + 1,
              [alert.severity]: (prev[alert.severity] || 0) + 1,
            }
          : prev
      );
    });
    return unsub;
  }, []);

  return (
    <div className="dashboard">
      {/* Header */}
      <header className="dash-header">
        <div className="logo">
          <span className="logo-icon">⬡</span>
          <span className="logo-text">LiveSOC</span>
          <span className="logo-sub">Security Operations Center</span>
        </div>
        <div className="header-right">
          {health && (
            <div className={`health-badge ${health.status}`}>
              <span className="h-dot" />
              {health.status.toUpperCase()}
            </div>
          )}
          <button className="btn-reset" onClick={() => setAlerts([])}>
            Clear View
          </button>
        </div>
      </header>

      {/* Stats row */}
      <div className="stats-row">
        <StatCard label="Total Alerts" value={stats?.total} color="#60a5fa" />
        <StatCard label="Critical" value={stats?.critical} color="#ff2d55" />
        <StatCard label="High" value={stats?.high} color="#ff9f0a" />
        <StatCard label="Medium" value={stats?.medium} color="#ffd60a" />
        <StatCard label="Low" value={stats?.low} color="#30d158" />
        <StatCard label="Unique Sources" value={stats?.unique_sources} color="#a78bfa" />
      </div>

      {/* Map + Live Feed row */}
      <div className="map-feed-row">
        <MapView alerts={alerts.filter((a) => a.latitude)} />
        <LiveFeed alerts={liveAlerts} />
      </div>

      {/* Filter bar */}
      <div className="filter-bar">
        <span className="filter-label">FILTER</span>
        {["", "critical", "high", "medium", "low"].map((sev) => (
          <button
            key={sev}
            className={`filter-btn ${severityFilter === sev ? "active" : ""}`}
            style={
              sev
                ? { "--fc": SEVERITY_CONFIG[sev]?.color }
                : { "--fc": "#60a5fa" }
            }
            onClick={() => setSeverityFilter(sev)}
          >
            {sev || "ALL"}
          </button>
        ))}
        <span className="filter-count">{alerts.length} events</span>
      </div>

      {/* Alert table */}
      {loading ? (
        <div className="loading-state">Initializing sensors…</div>
      ) : (
        <AlertTable alerts={alerts} onRowClick={setSelected} />
      )}

      {/* Detail drawer */}
      {selected && (
        <div className="detail-overlay" onClick={() => setSelected(null)}>
          <div className="detail-drawer" onClick={(e) => e.stopPropagation()}>
            <button className="drawer-close" onClick={() => setSelected(null)}>✕</button>
            <h2 className="drawer-title">{selected.alert_type}</h2>
            <div
              className="drawer-sev"
              style={{ color: SEVERITY_CONFIG[selected.severity]?.color }}
            >
              {selected.severity?.toUpperCase()} — Score: {selected.score?.toFixed(1)}
            </div>
            <table className="drawer-table">
              <tbody>
                {[
                  ["Timestamp", new Date(selected.timestamp).toLocaleString()],
                  ["Source IP", selected.source_ip],
                  ["Dest IP", selected.dest_ip],
                  ["Ports", `${selected.source_port || "?"} → ${selected.dest_port || "?"}`],
                  ["Protocol", selected.protocol],
                  ["Category", selected.category],
                  ["Country", selected.country],
                  ["City", selected.city],
                  ["Source", selected.source],
                ].map(([k, v]) => (
                  <tr key={k}>
                    <td className="dk">{k}</td>
                    <td className="dv mono">{v || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {selected.threat_intel && (
              <>
                <h3 className="drawer-section">Threat Intel</h3>
                <pre className="raw-json">
                  {JSON.stringify(selected.threat_intel, null, 2)}
                </pre>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}