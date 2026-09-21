import { useEffect, useRef } from "react";

// Leaflet is loaded via CDN in index.html
// This component renders a dark-themed world map with attack origin markers.

const SEVERITY_COLORS = {
  critical: "#ff2d55",
  high: "#ff9f0a",
  medium: "#ffd60a",
  low: "#30d158",
};

const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#039;",
}[character]));

export function MapView({ alerts }) {
  const mapRef = useRef(null);
  const leafletMap = useRef(null);
  const markerLayer = useRef(null);

  useEffect(() => {
    if (!window.L || leafletMap.current) return;

    leafletMap.current = window.L.map(mapRef.current, {
      center: [20, 0],
      zoom: 2,
      zoomControl: false,
      attributionControl: false,
    });

    window.L.tileLayer(
      "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
      { subdomains: "abcd", maxZoom: 19 }
    ).addTo(leafletMap.current);

    window.L.control.zoom({ position: "bottomright" }).addTo(leafletMap.current);
    markerLayer.current = window.L.layerGroup().addTo(leafletMap.current);

    return () => {
      leafletMap.current?.remove();
      leafletMap.current = null;
      markerLayer.current = null;
    };
  }, []);

  useEffect(() => {
    if (!leafletMap.current || !window.L || !markerLayer.current) return;

    markerLayer.current.clearLayers();

    alerts.forEach((alert) => {
      if (!Number.isFinite(alert.latitude) || !Number.isFinite(alert.longitude)) return;
      const color = SEVERITY_COLORS[alert.severity] || "#888";

      const icon = window.L.divIcon({
        className: "",
        html: `<div style="
          width:12px;height:12px;border-radius:50%;
          background:${color};
          box-shadow:0 0 8px ${color}, 0 0 20px ${color}44;
          border:2px solid rgba(255,255,255,0.25);
        "></div>`,
        iconSize: [12, 12],
        iconAnchor: [6, 6],
      });

      const marker = window.L.marker([alert.latitude, alert.longitude], { icon })
        .addTo(leafletMap.current)
        .bindPopup(`
          <div style="font-family:monospace;font-size:12px;color:#eee;background:#111;padding:6px;border-radius:4px">
            <b style="color:${color}">${escapeHtml(alert.severity).toUpperCase()}</b> — ${escapeHtml(alert.alert_type)}<br/>
            <span style="color:#aaa">${escapeHtml(alert.source_ip)}</span> → ${escapeHtml(alert.dest_ip)}<br/>
            ${escapeHtml(alert.country)} ${alert.city ? `(${escapeHtml(alert.city)})` : ""}
          </div>
        `, { className: "dark-popup" });

      markerLayer.current.addLayer(marker);
    });
  }, [alerts]);

  return (
    <div className="map-container">
      <div ref={mapRef} style={{ width: "100%", height: "100%" }} />
    </div>
  );
}
