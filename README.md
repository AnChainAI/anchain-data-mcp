# AnChain Data MCP

A Model Context Protocol (MCP) server for the AnChain.AI Data API - a comprehensive blockchain intelligence platform powered by AI/ML that enables developers, investigators, and compliance officers to manage risk and ensure regulatory compliance in Web3 applications.

## Features

### Intelligence APIs
Core risk assessment and entity identification for blockchain addresses and transactions, delivering real-time risk scores, category labels, and suspicious activity detection.

### Analytics APIs
Advanced behavioral analysis and transaction flow tracking, including statistical insights, attribution analysis, transaction graphs, automated tracing, and smart contract analysis.

### Sanctions APIs
Comprehensive screening against global watchlists, including OFAC and international sanctions databases from multiple jurisdictions (US, EU, UK, Canada, Australia, Switzerland, Israel, Japan, UN, South Africa, and Zambia).

### Insights APIs
Curated threat intelligence and industry news aggregation from specialized blockchain and cryptocurrency sources.

## Requirements

- Python 3.12 or higher
- `uv` package manager

## Installation

1. Install `uv` if you haven't already:
```bash
pip install uv
```

2. Clone this repository:
```bash
git clone <repository-url>
cd anchain-data-mcp
```

3. Initialize the project and install dependencies:
```bash
uv init
uv sync
```

This will set up the virtual environment and install all required packages from your project configuration.

## Configuration

### Get Your API Key

Sign up and obtain your AnChain API key at: https://data.anchainai.com

Full API documentation is also available at the same URL.

### Configure Claude Desktop

Add the following configuration to your Claude Desktop config file:

**MacOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows**: `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "anchain-data": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/anchain-data-mcp",
        "mcp_server.py",
        "--ANCHAIN_APIKEY",
        "your_api_key_here"
      ]
    }
  }
}
```

Replace `/path/to/anchain-data-mcp` with the actual path to your project folder and `your_api_key_here` with your AnChain API key.

### Configure Cursor

Add the following to your Cursor MCP settings file:

**MacOS**: `~/Library/Application Support/Cursor/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`

**Windows**: `%APPDATA%/Cursor/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`

```json
{
  "mcpServers": {
    "anchain-data": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/anchain-data-mcp",
        "mcp_server.py",
        "--ANCHAIN_APIKEY",
        "your_api_key_here"
      ]
    }
  }
}
```

### Configure Other MCP-Compatible Platforms

For other AI platforms that support the Model Context Protocol (such as Zed, Sourcegraph Cody, or custom integrations), add a similar configuration to their MCP settings file:

```json
{
  "mcpServers": {
    "anchain-data": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/anchain-data-mcp",
        "mcp_server.py",
        "--ANCHAIN_APIKEY",
        "your_api_key_here"
      ]
    }
  }
}
```

Consult your platform's documentation for the exact location of the MCP configuration file.

## Usage

Once configured, the AnChain Data MCP server will be available in Claude Desktop. You can ask Claude to:

- Assess blockchain address risks
- Screen addresses against sanctions lists
- Analyze transaction patterns
- Investigate smart contracts
- Access blockchain intelligence and news

The MCP server exposes all AnChain.AI Data API capabilities as tools that Claude can use automatically based on your requests.


## Documentation

For detailed API documentation and capabilities, visit: https://data.anchainai.com

## License

This project is licensed under the GPL License.

## Support

For issues, questions, or feature requests, please refer to the AnChain.AI documentation or contact support through https://data.anchainai.com