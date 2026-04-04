import { useEffect, useRef } from "react";

const SEVERITY_COLORS = {
  critical: "#ff2d55",
  high: "#ff9f0a",
  medium: "#ffd60a",
  low: "#30d158",
};

export function LiveFeed({ alerts }) {
  const feedRef = useRef(null);

  // Auto-scroll to bottom on new alert
  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [alerts]);

  const fmtTime = (ts) =>
    new Date(ts).toLocaleTimeString("en-GB", { hour12: false });

  return (
    <div className="live-feed" ref={feedRef}>
      <div className="feed-header">
        <span className="pulse-dot" />
        LIVE FEED
      </div>
      <div className="feed-entries">
        {[...alerts].reverse().map((alert, i) => {
          const color = SEVERITY_COLORS[alert.severity] || "#888";
          return (
            <div key={alert.id ?? i} className="feed-entry" style={{ "--accent": color }}>
              <span className="fe-time mono">{fmtTime(alert.timestamp)}</span>
              <span className="fe-sev" style={{ color }}>
                [{alert.severity?.toUpperCase()}]
              </span>
              <span className="fe-ip mono">{alert.source_ip}</span>
              <span className="fe-arrow">→</span>
              <span className="fe-sig">{alert.alert_type}</span>
            </div>
          );
        })}
        {alerts.length === 0 && (
          <div style={{ opacity: 0.3, padding: "1rem", fontSize: "0.8rem" }}>
            Awaiting events…
          </div>
        )}
      </div>
    </div>
  );
}