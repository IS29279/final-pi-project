import pytest
from unittest.mock import patch, MagicMock

from FinalApp import create_app


# ── Fixture: fresh app + test client for every test ─────────────────────────
@pytest.fixture
def client():
    """
    Builds a fresh app instance in testing mode and yields a test client.
    Testing mode causes exceptions to surface instead of becoming 500 responses,
    which makes failing tests much easier to diagnose.
    """
    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        # Log in so the session cookie is set for all subsequent requests
        client.post("/login", data={
            "username": "admin",
            "password": "K7mT-vR2nQ9xLpWz"
        })
        yield client


# ── /scan/start ──────────────────────────────────────────────────────────────

class TestScanStart:
    """Tests for POST /scan/start"""

    @patch("FinalApp.threading.Thread")
    def test_start_redirects_on_success(self, mock_thread, client):
        """
        A well-formed POST should redirect back to the dashboard (302).
        The route calls redirect(url_for('dashboard')) — not jsonify().
        Thread is patched so no real scan runs.
        """
        mock_thread.return_value = MagicMock()

        response = client.post("/scan/start", data={
            "target":    "192.168.1.0/24",
            "interface": "wlan1",
            "duration":  "30"
        })

        assert response.status_code == 302, (
            f"Expected a 302 redirect to dashboard, got {response.status_code}"
        )

    @patch("FinalApp.threading.Thread")
    def test_start_redirects_to_dashboard(self, mock_thread, client):
        """
        The redirect should point to / (the dashboard route).
        """
        mock_thread.return_value = MagicMock()

        response = client.post("/scan/start", data={
            "target":    "192.168.1.0/24",
            "interface": "wlan1",
            "duration":  "30"
        })

        assert response.headers["Location"].endswith("/"), (
            f"Expected redirect to '/', got: {response.headers.get('Location')}"
        )

    @patch("FinalApp.threading.Thread")
    def test_start_uses_form_defaults(self, mock_thread, client):
        """
        /scan/start has defaults for all three fields (target, duration, interface),
        so an empty POST body should still redirect rather than crash.
        """
        mock_thread.return_value = MagicMock()

        response = client.post("/scan/start", data={})

        assert response.status_code == 302, (
            "An empty form POST should still redirect using field defaults"
        )

    @patch("FinalApp.threading.Thread")
    def test_start_spawns_background_thread(self, mock_thread, client):
        """
        Submitting the scan form should create and start exactly one
        background thread inside FinalApp.py.
        """
        mock_instance = MagicMock()
        mock_thread.return_value = mock_instance

        client.post("/scan/start", data={
            "target":    "10.0.0.0/24",
            "interface": "eth0",
            "duration":  "15"
        })

        mock_thread.assert_called_once()
        mock_instance.start.assert_called_once()


# ── /api/scans ───────────────────────────────────────────────────────────────

class TestApiScans:
    """Tests for GET /api/scans"""

    def test_scans_returns_200(self, client):
        """Endpoint should always respond, even with an empty database."""
        response = client.get("/api/scans")
        assert response.status_code == 200

    def test_scans_returns_dict_with_scans_key(self, client):
        """
        The route returns jsonify({"scans": [...]}), so the top-level
        response must be a dict containing a "scans" key.
        """
        response = client.get("/api/scans")
        data = response.get_json()
        assert isinstance(data, dict), (
            f"Expected a JSON dict from /api/scans, got: {type(data).__name__}"
        )
        assert "scans" in data, (
            f"Expected a 'scans' key in the response, got keys: {list(data.keys())}"
        )

    def test_scans_key_is_a_list(self, client):
        """The value of the 'scans' key must be a list (empty or otherwise)."""
        response = client.get("/api/scans")
        data = response.get_json()
        assert isinstance(data["scans"], list), (
            f"Expected data['scans'] to be a list, got: {type(data['scans']).__name__}"
        )

    @patch("FinalApp.threading.Thread")
    def test_scans_does_not_crash_after_scan_started(self, mock_thread, client):
        """
        Polling /api/scans immediately after starting a scan should not
        raise any exceptions or return a 500.
        """
        mock_thread.return_value = MagicMock()

        client.post("/scan/start", data={
            "target":    "192.168.1.0/24",
            "interface": "wlan1",
            "duration":  "10"
        })

        response = client.get("/api/scans")
        assert response.status_code == 200


# ── /scan/stop ───────────────────────────────────────────────────────────────

class TestScanStop:
    """Tests for POST /scan/stop"""

    def test_stop_with_no_active_scan_returns_200(self, client):
        """
        Calling stop when nothing is running should not crash.
        The route always returns jsonify({"stopped": True, ...}) so 200
        is the only expected response — there is no 404 path.
        """
        response = client.post("/scan/stop")
        assert response.status_code == 200, (
            f"Expected 200 when stopping with no active scan, got {response.status_code}"
        )

    def test_stop_returns_json(self, client):
        """
        /scan/stop returns jsonify({"stopped": True, "session_id": ...}).
        The response must always be valid JSON.
        """
        response = client.post("/scan/stop")
        data = response.get_json()
        assert data is not None, "Expected a JSON response body from /scan/stop"
        assert "stopped" in data, (
            f"Expected a 'stopped' key in the response, got: {list(data.keys())}"
        )

    @patch("FinalApp.threading.Thread")
    def test_stop_after_start_returns_200(self, mock_thread, client):
        """
        The typical user flow: start a scan then stop it early.
        Should complete without errors.
        """
        mock_thread.return_value = MagicMock()

        client.post("/scan/start", data={
            "target":    "192.168.1.0/24",
            "interface": "wlan1",
            "duration":  "60"
        })

        response = client.post("/scan/stop")
        assert response.status_code == 200, (
            f"Expected 200 after stopping an active scan, got {response.status_code}"
        )

    @patch("FinalApp.threading.Thread")
    def test_double_stop_does_not_crash(self, mock_thread, client):
        """
        Calling stop twice (e.g. user double-clicks the Stop button) should
        be handled gracefully — the second call is effectively a no-op.
        """
        mock_thread.return_value = MagicMock()

        client.post("/scan/start", data={
            "target":    "192.168.1.0/24",
            "interface": "wlan1",
            "duration":  "60"
        })

        client.post("/scan/stop")
        second_stop = client.post("/scan/stop")

        assert second_stop.status_code == 200, (
            "A second stop call should return 200, not a server error"
        )


# ── /api/scan-detail/<id> ────────────────────────────────────────────────────

class TestScanDetail:
    """Tests for GET /api/scan-detail/<id>"""

    def test_nonexistent_session_returns_empty_lists(self):
        """
        get_hosts() and get_traffic_findings() in db.py both return []
        for an ID that doesn't exist — so the route always returns 200
        with empty lists rather than 404.
        """
        app = create_app()
        app.config["TESTING"] = True
        with app.test_client() as client:
            client.post("/login", data={
                "username": "admin",
                "password": "K7mT-vR2nQ9xLpWz"
            })
            fake_uuid = "00000000-0000-0000-0000-000000000000"
            response = client.get(f"/api/scan-detail/{fake_uuid}")
            assert response.status_code == 200
            data = response.get_json()
            assert data["hosts"]   == [], (
                f"Expected empty hosts list for nonexistent session, got: {data['hosts']}"
            )
            assert data["traffic"] == [], (
                f"Expected empty traffic list for nonexistent session, got: {data['traffic']}"
            )

    def test_response_has_hosts_and_traffic_keys(self):
        """
        The response dict must always contain both 'hosts' and 'traffic' keys,
        regardless of whether the session exists.
        """
        app = create_app()
        app.config["TESTING"] = True
        with app.test_client() as client:
            client.post("/login", data={
                "username": "admin",
                "password": "K7mT-vR2nQ9xLpWz"
            })
            fake_uuid = "00000000-0000-0000-0000-000000000001"
            response = client.get(f"/api/scan-detail/{fake_uuid}")
            data = response.get_json()
            assert "hosts"   in data, f"Missing 'hosts' key in response: {data}"
            assert "traffic" in data, f"Missing 'traffic' key in response: {data}"

    def test_malformed_id_does_not_crash(self):
        """
        A non-UUID value in the URL should not cause a 500 — the DB query
        simply returns empty results for any string that matches no rows.
        """
        app = create_app()
        app.config["TESTING"] = True
        with app.test_client() as client:
           client.post("/login", data={
                "username": "admin",
                "password": "K7mT-vR2nQ9xLpWz"
            })
                for bad_id in ["abc", "not-a-uuid", "99999"]:
                    response = client.get(f"/api/scan-detail/{bad_id}")
                    assert response.status_code == 200, (
                        f"ID '{bad_id}' caused a {response.status_code} — expected 200 with empty lists"
                    )
