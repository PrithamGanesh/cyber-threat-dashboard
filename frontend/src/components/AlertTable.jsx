import { useMemo, useState } from "react";

const SEVERITY_CONFIG = {
  critical: { color: "#ff2d55", bg: "rgba(255,45,85,0.12)", label: "CRIT" },
  high:     { color: "#ff9f0a", bg: "rgba(255,159,10,0.12)", label: "HIGH" },
  medium:   { color: "#ffd60a", bg: "rgba(255,214,10,0.12)", label: "MED" },
  low:      { color: "#30d158", bg: "rgba(48,209,88,0.12)",  label: "LOW"  },
};

const timeFormatter = new Intl.DateTimeFormat("en-GB", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

export function AlertTable({ alerts, onRowClick }) {
  const [sort, setSort] = useState({ key: "timestamp", dir: "desc" });

  const sorted = useMemo(() => [...alerts].sort((a, b) => {
    const av = sort.key === "timestamp" ? Date.parse(a.timestamp) : (a[sort.key] ?? "");
    const bv = sort.key === "timestamp" ? Date.parse(b.timestamp) : (b[sort.key] ?? "");
    if (av < bv) return sort.dir === "asc" ? -1 : 1;
    if (av > bv) return sort.dir === "asc" ? 1 : -1;
    return 0;
  }), [alerts, sort]);

  const toggleSort = (key) =>
    setSort((s) => ({ key, dir: s.key === key && s.dir === "asc" ? "desc" : "asc" }));

  const fmtTime = (ts) => timeFormatter.format(new Date(ts));

  return (
    <div className="alert-table-wrap">
      <table className="alert-table">
        <thead>
          <tr>
            {[
              { key: "timestamp", label: "TIME" },
              { key: "severity",  label: "SEV"  },
              { key: "score",     label: "SCORE" },
              { key: "source_ip", label: "SRC IP" },
              { key: "dest_ip",   label: "DST IP" },
              { key: "protocol",  label: "PROTO" },
              { key: "alert_type",label: "SIGNATURE" },
              { key: "country",   label: "GEO" },
            ].map(({ key, label }) => (
              <th key={key} aria-sort={sort.key === key ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}>
                <button type="button" onClick={() => toggleSort(key)} className="sort-button">
                  {label}
                  {sort.key === key && (
                    <span className="sort-arrow" aria-hidden="true">{sort.dir === "asc" ? " ↑" : " ↓"}</span>
                  )}
                </button>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((alert) => {
            const cfg = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.low;
            return (
              <tr
                key={alert.id}
                className="alert-row"
                onClick={() => onRowClick?.(alert)}
                style={{ "--row-accent": cfg.color }}
              >
                <td className="mono">{fmtTime(alert.timestamp)}</td>
                <td>
                  <span
                    className="badge"
                    style={{ color: cfg.color, background: cfg.bg, borderColor: cfg.color }}
                  >
                    {cfg.label}
                  </span>
                </td>
                <td>
                  <span
                    className="score-bar"
                    style={{ "--pct": `${alert.score}%`, "--clr": cfg.color }}
                  >
                    {Number(alert.score || 0).toFixed(0)}
                  </span>
                </td>
                <td className="mono ip">{alert.source_ip}</td>
                <td className="mono ip">{alert.dest_ip}</td>
                <td className="proto">{alert.protocol || "—"}</td>
                <td className="sig" title={alert.alert_type}>{alert.alert_type}</td>
                <td>{alert.country || "—"}</td>
              </tr>
            );
          })}
          {sorted.length === 0 && (
            <tr>
              <td colSpan={8} style={{ textAlign: "center", opacity: 0.4, padding: "2rem" }}>
                No alerts
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
