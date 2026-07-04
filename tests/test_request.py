"""Offline unit tests for the AnChain MCP HTTP helper (no API key or network)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import pytest
from unittest.mock import patch, MagicMock

import mcp_server
from fastmcp.exceptions import ToolError


def _resp(status=200, json_data=None, bad_json=False, text=""):
    m = MagicMock()
    m.status_code = status
    m.ok = 200 <= status < 400
    m.text = text
    if bad_json:
        m.json.side_effect = ValueError("no json")
    else:
        m.json.return_value = json_data
    return m


def test_success_returns_parsed_json_and_always_sets_timeout():
    with patch("mcp_server.requests.request", return_value=_resp(200, {"ok": True})) as rq:
        assert mcp_server._request("GET", url="http://x") == {"ok": True}
        assert "timeout" in rq.call_args.kwargs  # never blocks forever


def test_http_error_status_raises_toolerror():
    with patch("mcp_server.requests.request", return_value=_resp(500, {"err_msg": "boom"}, text="boom")):
        with pytest.raises(ToolError):
            mcp_server._request("GET", url="http://x")


def test_json_envelope_error_on_http_200_raises_toolerror():
    # the AnChain API returns {"status": 401, "err_msg": ...} envelopes even on HTTP 200
    with patch("mcp_server.requests.request", return_value=_resp(200, {"status": 401, "err_msg": "Invalid user"})):
        with pytest.raises(ToolError):
            mcp_server._request("GET", url="http://x")


def test_benign_numeric_status_field_without_err_msg_is_not_an_error():
    # a successful payload that merely contains a numeric "status" field must not be flagged
    payload = {"status": 404, "data": "a legitimate result"}
    with patch("mcp_server.requests.request", return_value=_resp(200, payload)):
        assert mcp_server._request("GET", url="http://x") == payload


def test_non_json_body_raises_toolerror():
    with patch("mcp_server.requests.request", return_value=_resp(502, bad_json=True, text="<html>bad gateway")):
        with pytest.raises(ToolError):
            mcp_server._request("GET", url="http://x")


def test_timeout_raises_toolerror():
    with patch("mcp_server.requests.request", side_effect=requests.exceptions.Timeout()):
        with pytest.raises(ToolError):
            mcp_server._request("GET", url="http://x")


def test_connection_error_raises_toolerror():
    with patch("mcp_server.requests.request", side_effect=requests.exceptions.ConnectionError()):
        with pytest.raises(ToolError):
            mcp_server._request("GET", url="http://x")


def test_get_and_post_wrappers_pass_method():
    with patch("mcp_server.requests.request", return_value=_resp(200, {"m": "ok"})) as rq:
        mcp_server._get(url="http://x")
        assert rq.call_args.args[0] == "GET"
        mcp_server._post(url="http://x")
        assert rq.call_args.args[0] == "POST"


def test_missing_api_key_raises_toolerror(monkeypatch):
    monkeypatch.setattr(mcp_server, "remote", False)
    monkeypatch.setattr(mcp_server, "anchain_apikey", None)
    with pytest.raises(ToolError):
        mcp_server.check_apikey()
