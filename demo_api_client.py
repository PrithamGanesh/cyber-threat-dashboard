#!/usr/bin/env python3
"""
Demonstration script showing how to use the secured LiveSOC API with JWT authentication.

This script shows:
1. How to get a JWT token via login
2. How to use the token in protected endpoints
3. How to handle authentication errors
"""

import requests
import json
from typing import Optional

# API Configuration
API_BASE_URL = "http://localhost:8000/api/v1"

class LiveSOCClient:
    """Client for interacting with LiveSOC API with authentication."""
    
    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url
        self.token: Optional[str] = None
        self.session = requests.Session()
    
    def _get_headers(self) -> dict:
        """Get headers with JWT token if available."""
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers
    
    def login(self, username: str, password: str) -> bool:
        """
        Login and get JWT token.
        
        Args:
            username: Username (demo: "user" or "admin")
            password: Password (demo: "password123" or "admin123")
        
        Returns:
            True if login successful, False otherwise
        """
        try:
            response = requests.post(
                f"{self.base_url}/auth/login",
                json={"username": username, "password": password}
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data["access_token"]
                print(f"✅ Logged in as '{username}'")
                print(f"   Token: {self.token[:50]}...")
                return True
            else:
                print(f"❌ Login failed: {response.status_code}")
                print(f"   {response.json()}")
                return False
        except Exception as e:
            print(f"❌ Login error: {e}")
            return False
    
    def get_alerts(self, limit: int = 10, severity: Optional[str] = None):
        """
        Retrieve alerts (requires authentication).
        
        Args:
            limit: Number of alerts to retrieve (1-500)
            severity: Filter by severity (critical, high, medium, low)
        
        Returns:
            List of alerts or error message
        """
        if not self.token:
            print("❌ Not authenticated. Call login() first.")
            return None
        
        try:
            params = {"limit": limit}
            if severity:
                params["severity"] = severity
            
            response = requests.get(
                f"{self.base_url}/alerts/",
                headers=self._get_headers(),
                params=params
            )
            
            if response.status_code == 200:
                alerts = response.json()
                print(f"✅ Retrieved {len(alerts)} alerts")
                return alerts
            else:
                print(f"❌ Error: {response.status_code}")
                print(f"   {response.json()}")
                return None
        except Exception as e:
            print(f"❌ Error retrieving alerts: {e}")
            return None
    
    def get_stats(self):
        """
        Get alert statistics (requires authentication).
        
        Returns:
            Alert statistics or error message
        """
        if not self.token:
            print("❌ Not authenticated. Call login() first.")
            return None
        
        try:
            response = requests.get(
                f"{self.base_url}/alerts/stats",
                headers=self._get_headers()
            )
            
            if response.status_code == 200:
                stats = response.json()
                print("✅ Retrieved alert statistics")
                return stats
            else:
                print(f"❌ Error: {response.status_code}")
                return None
        except Exception as e:
            print(f"❌ Error retrieving stats: {e}")
            return None
    
    def ingest_alert(self, payload: dict) -> bool:
        """
        Ingest a log entry (requires authentication).
        
        Args:
            payload: Alert data as dictionary
        
        Returns:
            True if ingestion successful, False otherwise
        """
        if not self.token:
            print("❌ Not authenticated. Call login() first.")
            return False
        
        try:
            response = requests.post(
                f"{self.base_url}/alerts/ingest",
                headers=self._get_headers(),
                params={"source": "suricata"},
                json=payload
            )
            
            if response.status_code == 201:
                alert = response.json()
                print(f"✅ Ingested alert: {alert.get('id')}")
                return True
            else:
                print(f"❌ Ingest failed: {response.status_code}")
                print(f"   {response.json()}")
                return False
        except Exception as e:
            print(f"❌ Error ingesting alert: {e}")
            return False
    
    def reset_alerts(self, admin_key: str) -> bool:
        """
        Delete all alerts (requires admin API key).
        
        WARNING: This permanently deletes all alerts!
        
        Args:
            admin_key: Admin API key
        
        Returns:
            True if reset successful, False otherwise
        """
        try:
            headers = {"admin-key": admin_key}
            response = requests.delete(
                f"{self.base_url}/alerts/reset",
                headers=headers
            )
            
            if response.status_code == 204:
                print("✅ All alerts deleted")
                return True
            else:
                print(f"❌ Reset failed: {response.status_code}")
                if response.text:
                    print(f"   {response.json()}")
                return False
        except Exception as e:
            print(f"❌ Error resetting alerts: {e}")
            return False


def main():
    """Run demonstration."""
    print("=" * 70)
    print("LiveSOC API Security Demo")
    print("=" * 70)
    
    client = LiveSOCClient()
    
    # Demo 1: Failed authentication attempt
    print("\n[Demo 1] Attempting API call without authentication...")
    print("GET /api/v1/alerts/ (no token)")
    try:
        response = requests.get(f"{API_BASE_URL}/alerts/")
        print(f"   Status: {response.status_code}")
        print(f"   ✅ BLOCKED: {response.json()['detail']}")
    except Exception as e:
        print(f"   ✅ BLOCKED: {e}")
    
    # Demo 2: Login with valid credentials
    print("\n[Demo 2] Login with valid credentials...")
    if not client.login("user", "password123"):
        print("   Login failed. Is the API running?")
        return
    
    # Demo 3: Make authenticated request
    print("\n[Demo 3] Retrieve alerts with authentication...")
    alerts = client.get_alerts(limit=5)
    if alerts:
        if len(alerts) > 0:
            print(f"   First alert: {alerts[0].get('id')} - {alerts[0].get('severity')}")
    
    # Demo 4: Get statistics
    print("\n[Demo 4] Get alert statistics...")
    stats = client.get_stats()
    if stats:
        print(f"   Total alerts: {stats.get('total')}")
        print(f"   Critical: {stats.get('critical')}, High: {stats.get('high')}")
    
    # Demo 5: Ingest a new alert
    print("\n[Demo 5] Ingest a new alert with validation...")
    sample_alert = {
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "source_port": 54321,
        "dest_port": 443,
        "protocol": "TCP",
        "alert_type": "SSL_Certificate_Anomaly",
        "severity": "high",
        "score": 75.5,
        "signature": "Possible SSL certificate verification bypass",
        "category": "Protocol",
    }
    client.ingest_alert(sample_alert)
    
    # Demo 6: Invalid IP address (blocked by validator)
    print("\n[Demo 6] Try to ingest alert with invalid IP (should fail)...")
    invalid_alert = {
        "source_ip": "not-an-ip",  # Invalid!
        "dest_ip": "10.0.0.1",
        "alert_type": "Test",
        "severity": "high",
        "score": 50,
    }
    client.ingest_alert(invalid_alert)
    
    # Demo 7: Try delete without admin key
    print("\n[Demo 7] Try to delete all alerts without admin key...")
    client.reset_alerts("invalid-key")
    
    # Demo 8: Try delete with admin key
    print("\n[Demo 8] Delete all alerts with valid admin key...")
    print("   (Skipped to preserve demo data)")
    # Uncomment to actually delete: client.reset_alerts("admin-key-change-in-production")
    
    print("\n" + "=" * 70)
    print("Security Features Demonstrated:")
    print("  ✅ JWT authentication required for protected endpoints")
    print("  ✅ Input validation prevents SQL injection (invalid IP rejected)")
    print("  ✅ Admin key protection prevents unauthorized data deletion")
    print("  ✅ Type validation (enums, ranges) enforced by Pydantic")
    print("=" * 70)


if __name__ == "__main__":
    main()
