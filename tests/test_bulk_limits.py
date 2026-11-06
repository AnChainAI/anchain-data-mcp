"""Exercise bulk validation through the MCP client without API requests."""
import unittest
from unittest.mock import Mock, patch

from fastmcp import Client

import mcp_server


TOOLS = ("bulk_address_label", "bulk_address_risk_score")


class BulkAddressLimitsTests(unittest.IsolatedAsyncioTestCase):
    async def test_schema_advertises_both_limits(self):
        async with Client(mcp_server.mcp) as client:
            tools = {tool.name: tool for tool in await client.list_tools()}
        for name in TOOLS:
            with self.subTest(tool=name):
                schema = tools[name].inputSchema["properties"]["addresses"]
                self.assertEqual(schema.get("minItems"), 1)
                self.assertEqual(schema.get("maxItems"), 10)

    async def test_invalid_batch_sizes_never_reach_api(self):
        with patch.object(mcp_server, "anchain_apikey", "test-key"), patch.object(
            mcp_server.requests, "post"
        ) as post:
            post.return_value.json.return_value = {"status": 200}
            async with Client(mcp_server.mcp) as client:
                for name in TOOLS:
                    for count in (0, 11):
                        with self.subTest(tool=name, count=count):
                            post.reset_mock()
                            result = await client.call_tool(
                                name,
                                {"proto": "eth", "addresses": ["0x123"] * count},
                                raise_on_error=False,
                            )
                            self.assertTrue(result.is_error)
                            post.assert_not_called()

    async def test_boundary_batch_sizes_preserve_payload_and_response(self):
        payload = {"status": 200, "data": [{"label": "example"}]}
        response = Mock()
        response.json.return_value = payload
        with patch.object(mcp_server, "anchain_apikey", "test-key"), patch.object(
            mcp_server.requests, "post", return_value=response
        ) as post:
            async with Client(mcp_server.mcp) as client:
                for name in TOOLS:
                    for count in (1, 10):
                        with self.subTest(tool=name, count=count):
                            addresses = ["0x123"] * count
                            result = await client.call_tool(
                                name, {"proto": "eth", "addresses": addresses}
                            )
                            self.assertFalse(result.is_error)
                            self.assertEqual(result.data, payload)
                            self.assertEqual(
                                post.call_args.kwargs["json"],
                                {"proto": "eth", "address": addresses},
                            )
                            post.reset_mock()


if __name__ == "__main__":
    unittest.main()
