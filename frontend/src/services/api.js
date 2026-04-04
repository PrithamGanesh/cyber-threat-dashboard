const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1";

// Configuration for exponential backoff retry logic
const RECONNECT_CONFIG = {
  initialDelay: 1000,    // Start with 1 second
  maxDelay: 30000,       // Cap at 30 seconds
  maxAttempts: 10,       // Give up after 10 attempts
};

export const api = {
  /**
   * Retrieve paginated alerts with optional filtering
   */
  async getAlerts({ skip = 0, limit = 100, severity, source_ip, alert_type } = {}) {
    const params = new URLSearchParams({ skip, limit });
    if (severity) params.set("severity", severity);
    if (source_ip) params.set("source_ip", source_ip);
    if (alert_type) params.set("alert_type", alert_type);
    
    const res = await fetch(`${BASE_URL}/alerts/?${params}`);
    if (!res.ok) {
      const error = new Error(`Alerts fetch failed: ${res.status}`);
      error.status = res.status;
      throw error;
    }
    return res.json();
  },

  /**
   * Get aggregated alert statistics (counts, top categories)
   */
  async getStats() {
    const res = await fetch(`${BASE_URL}/alerts/stats`);
    if (!res.ok) {
      const error = new Error(`Stats fetch failed: ${res.status}`);
      error.status = res.status;
      throw error;
    }
    return res.json();
  },

  /**
   * Get system health status (API, database, Redis)
   */
  async getHealth() {
    const res = await fetch(`${BASE_URL}/health/`);
    if (!res.ok) {
      const error = new Error(`Health fetch failed: ${res.status}`);
      error.status = res.status;
      throw error;
    }
    return res.json();
  },

  /**
   * Subscribe to real-time alert stream via Server-Sent Events
   * Implements exponential backoff reconnection logic
   * 
   * @param {Function} onAlert - Callback when new alert arrives
   * @param {Function} onError - Callback on stream error
   * @returns {Function} Unsubscribe function to close the stream
   */
  subscribeToAlerts(onAlert, onError) {
    let reconnectAttempts = 0;
    let reconnectDelay = RECONNECT_CONFIG.initialDelay;
    let reconnectTimeout = null;
    let es = null;

    const connect = () => {
      try {
        es = new EventSource(`${BASE_URL}/alerts/stream`);
        
        es.onmessage = (e) => {
          try {
            const alert = JSON.parse(e.data);
            onAlert(alert);
            // Reset reconnection attempts on successful message
            reconnectAttempts = 0;
            reconnectDelay = RECONNECT_CONFIG.initialDelay;
          } catch (err) {
            console.error("Failed to parse alert message:", err);
            // Don't call onError for parse failures, just log
          }
        };

        es.onerror = (err) => {
          console.error("EventSource error:", err);
          es.close();
          
          // Attempt reconnection with exponential backoff
          if (reconnectAttempts < RECONNECT_CONFIG.maxAttempts) {
            reconnectAttempts++;
            reconnectDelay = Math.min(
              reconnectDelay * 1.5,
              RECONNECT_CONFIG.maxDelay
            );
            console.warn(
              `Reconnecting to alert stream (attempt ${reconnectAttempts}/${RECONNECT_CONFIG.maxAttempts}) in ${reconnectDelay}ms`
            );
            reconnectTimeout = setTimeout(connect, reconnectDelay);
          } else {
            console.error("Max reconnection attempts reached. Alert stream unavailable.");
            if (onError) onError(err);
          }
        };
      } catch (err) {
        console.error("Failed to create EventSource:", err);
        if (onError) onError(err);
      }
    };

    // Initial connection
    connect();

    // Return unsubscribe function
    return () => {
      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
      }
      if (es) {
        es.close();
      }
    };
  },
};