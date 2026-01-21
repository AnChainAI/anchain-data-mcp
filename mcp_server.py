#!/usr/bin/env python3
"""
AnChain.AI MCP Server for AML Compliance and Crypto Screening
Copyright (c) 2025 AnChain.AI
Authors: Shao Liang, Victor Fang. 
Contact: Info AT anchain.ai
All rights reserved.

This software provides MCP (Model Context Protocol) tools for AML (Anti Money Laundering):
- Cryptocurrency address screening and risk assessment
- Global sanctions list screening for individuals and entities  
- IP address geolocation and sanctions compliance checking
- More data sources coming. 

For more information, visit: https://anchain.ai
"""

import os
import sys
import requests
import argparse
from typing import Literal, Optional
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers
from fastmcp.exceptions import FastMCPError, ValidationError, NotFoundError

# Create an MCP server
mcp = FastMCP("AnChain.AI")
API_BASE_URL = "https://api.anchainai.com"
anchain_apikey = None
remote = False

# ============================================================================
# INTELLIGENCE APIs
# ============================================================================

@mcp.tool()
def screen_ip_address(ip_address: str) -> dict:
    """Analyze IP geolocation data and sanctions status to support regional compliance checks.
    
    Args:
        ip_address: IP address to screen (IPv4 format, e.g. 1.2.3.4)
    
    Cost: 5 credits
    """
    apikey = check_apikey()
    res = requests.get(
        url=f"{API_BASE_URL}/api/intel/ip/geo",
        params={"ip_address": ip_address},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

@mcp.tool()
def get_address_label(proto: str, address: str) -> dict:
    """Retrieve the category label for a blockchain address, including the associated entity when available.
    
    Args:
        proto: Blockchain protocol (btc, eth, xlm, xmr, bnb, matic, avax, sol, trx, ada, dot, ltc, bch, algo, xrp)
        address: Blockchain address to query (e.g. 0x2f389ce8bd8ff92de3402ffce4691d17fc4f6535)
    
    Cost: 5 credits
    """
    apikey = check_apikey()
    res = requests.get(
        url=f"{API_BASE_URL}/api/intel/address/label",
        params={"proto": proto, "address": address},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

@mcp.tool()
def get_address_risk_score(proto: str, address: str) -> dict:
    """Retrieve an address risk score (0-100), risk level (1-4), category, and associated entity.
    
    Args:
        proto: Blockchain protocol (btc, eth, xlm, xmr, bnb, matic, avax, sol, trx, ada, dot, ltc, bch, algo, xrp)
        address: Blockchain address to query (e.g. 1ECeZBxCVJ8Wm2JSN3Cyc6rge2gnvD3W5K)
    
    Cost: 10 credits
    """
    apikey = check_apikey()
    res = requests.get(
        url=f"{API_BASE_URL}/api/intel/address/score",
        params={"proto": proto, "address": address},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

@mcp.tool()
def bulk_address_label(proto: str, addresses: list[str]) -> dict:
    """Retrieve address category labels and related entity information for multiple blockchain addresses (up to 10) in a single request.
    
    Args:
        proto: Blockchain protocol (btc, eth, xlm, xmr, bnb, matic, avax, sol, trx, ada, dot, ltc, bch, algo, xrp)
        addresses: List of blockchain addresses to query (1-10 addresses)
    
    Cost: 50 credits
    """
    apikey = check_apikey()
    res = requests.post(
        url=f"{API_BASE_URL}/api/intel/address/label/bulk",
        json={"proto": proto, "address": addresses},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

@mcp.tool()
def bulk_address_risk_score(proto: str, addresses: list[str]) -> dict:
    """Retrieve address risk scores, risk levels, and categories for multiple blockchain addresses (up to 10) in one request.
    
    Args:
        proto: Blockchain protocol (btc, eth, xlm, xmr, bnb, matic, avax, sol, trx, ada, dot, ltc, bch, algo, xrp)
        addresses: List of blockchain addresses to query (1-10 addresses)
    
    Cost: 100 credits
    """
    apikey = check_apikey()
    res = requests.post(
        url=f"{API_BASE_URL}/api/intel/address/score/bulk",
        json={"proto": proto, "address": addresses},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

@mcp.tool()
def get_address_suspicious_activities(proto: str, address: str) -> dict:
    """Retrieve suspicious activity associated with a blockchain address, along with related risk scores, levels, and categories.
    
    Args:
        proto: Blockchain protocol (btc, eth, xlm, xmr, bnb, matic, avax, sol, trx, ada, dot, ltc, bch, algo, xrp)
        address: Blockchain address to query (e.g. 1ECeZBxCVJ8Wm2JSN3Cyc6rge2gnvD3W5K)
    
    Cost: 50 credits
    """
    apikey = check_apikey()
    res = requests.get(
        url=f"{API_BASE_URL}/api/intel/address/suspicious-activities",
        params={"proto": proto, "address": address},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

@mcp.tool()
def get_transaction_detail(proto: str, hash: str) -> dict:
    """Retrieve detailed on-chain information for a specific blockchain transaction.
    
    Args:
        proto: Blockchain protocol (btc, eth, xrp, hash)
        hash: Transaction hash (e.g. 0xfd04466bb91ec4270172acffe187eea57145a906de9b488a0f410ade1569760e)
    
    Cost: 50 credits
    """
    apikey = check_apikey()
    res = requests.get(
        url=f"{API_BASE_URL}/api/intel/transaction",
        params={"proto": proto, "hash": hash},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

# ============================================================================
# ANALYTICS APIs
# ============================================================================

@mcp.tool()
def get_address_stats(proto: str, address: str) -> dict:
    """Retrieve statistical insights for a blockchain address, including transaction volume, frequency, and behavioral patterns.
    
    Args:
        proto: Blockchain protocol (btc, eth, xlm)
        address: Blockchain address to analyze (e.g. bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h)
    
    Cost: 100 credits
    """
    apikey = check_apikey()
    res = requests.get(
        url=f"{API_BASE_URL}/api/analytics/address/stats",
        params={"proto": proto, "address": address},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

@mcp.tool()
def get_address_attribution(proto: str, address: str) -> dict:
    """Analyze inflow and outflow activity of blockchain wallet addresses with entity-based attribution and percentage breakdowns.
    
    Args:
        proto: Blockchain protocol (btc, eth, xlm)
        address: Blockchain address to query (e.g. bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h)
    
    Cost: 200 credits
    """
    apikey = check_apikey()
    res = requests.get(
        url=f"{API_BASE_URL}/api/analytics/address/attribution",
        params={"proto": proto, "address": address},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

@mcp.tool()
def auto_trace_address(proto: str, address: str, direct: str, time_from: int, time_to: int) -> dict:
    """Automatically trace the flow of transactions from a wallet address across multiple hops. May take up to 5 minutes.
    
    Args:
        proto: Blockchain protocol (btc, eth, trx, xrp)
        address: Blockchain address to trace (e.g. 1ECeZBxCVJ8Wm2JSN3Cyc6rge2gnvD3W5K)
        direct: Transaction direction filter (in, out)
        time_from: Start timestamp for analysis (Unix timestamp, e.g. 1577836800)
        time_to: End timestamp for analysis (Unix timestamp, e.g. 1609459200)
    
    Cost: 200 credits
    """
    apikey = check_apikey()
    res = requests.post(
        url=f"{API_BASE_URL}/api/analytics/auto_trace",
        json={
            "proto": proto,
            "address": address,
            "direct": direct,
            "time_from": time_from,
            "time_to": time_to
        },
        headers={"X-API-KEY": apikey}
    )
    return res.json()

@mcp.tool()
def get_transaction_graph(proto: str, hash: str) -> dict:
    """Retrieve detailed transaction data with graph structures suitable for visualization and relationship analysis.
    
    Args:
        proto: Blockchain protocol (currently only eth supported)
        hash: Transaction hash (e.g. 0xfd04466bb91ec4270172acffe187eea57145a906de9b488a0f410ade1569760e)
    
    Cost: 100 credits
    """
    apikey = check_apikey()
    res = requests.get(
        url=f"{API_BASE_URL}/api/analytics/transaction/graph",
        params={"proto": proto, "hash": hash},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

@mcp.tool()
def get_smart_contract_code(proto: str, contract_address: str) -> dict:
    """Analyze smart contract source code and related execution behavior to understand contract logic and activity.
    
    Args:
        proto: Blockchain protocol (eth, bnb)
        contract_address: Smart contract address to analyze (e.g. 0xe924a9989d5bf8e8dea744deb390e6f4015b470c)
    
    Cost: 300 credits
    """
    apikey = check_apikey()
    res = requests.get(
        url=f"{API_BASE_URL}/api/analytics/contract/code",
        params={"proto": proto, "contract_address": contract_address},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

@mcp.tool()
def get_contract_transaction(proto: str, transaction_hash: str) -> dict:
    """Retrieve detailed information for smart contract transactions, including input data, state changes, and execution results.
    
    Args:
        proto: Blockchain protocol (eth, bnb)
        transaction_hash: Transaction hash to analyze (e.g. 0xfd04466bb91ec4270172acffe187eea57145a906de9b488a0f410ade1569760e)
    
    Cost: 300 credits
    """
    apikey = check_apikey()
    res = requests.get(
        url=f"{API_BASE_URL}/api/analytics/contract/transaction",
        params={"proto": proto, "transaction_hash": transaction_hash},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

# ============================================================================
# SANCTIONS APIs
# ============================================================================

@mcp.tool()
def screen_ofac_address(address: str) -> dict:
    """Check whether a blockchain address is associated with entities listed on the OFAC sanctions list.
    
    Args:
        address: Blockchain address to screen (e.g. 1ECeZBxCVJ8Wm2JSN3Cyc6rge2gnvD3W5K)
    
    Cost: 5 credits
    """
    apikey = check_apikey()
    res = requests.get(
        url=f"{API_BASE_URL}/api/sanctions/ofac/address",
        params={"address": address},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

@mcp.tool()
def search_ofac(
    type: Optional[str] = None,
    name: Optional[str] = None,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    id: Optional[str] = None,
    address: Optional[str] = None,
    city: Optional[str] = None,
    state: Optional[str] = None,
    country: Optional[str] = None
) -> dict:
    """Search the OFAC sanctions database using exact field matching across names, identifiers, and related attributes.
    
    Args:
        type: Entity type (individual, entity, vessel, aircraft)
        name: Full name
        first_name: First name (for individuals)
        last_name: Last name (for individuals)
        id: Crypto wallet addresses or identification numbers
        address: Street address
        city: City name
        state: State or province
        country: Country or nationality
    
    Cost: 10 credits
    """
    apikey = check_apikey()
    filters = {}
    if type: filters["type"] = type
    if name: filters["name"] = name
    if first_name: filters["first_name"] = first_name
    if last_name: filters["last_name"] = last_name
    if id: filters["id"] = id
    if address: filters["address"] = address
    if city: filters["city"] = city
    if state: filters["state"] = state
    if country: filters["country"] = country
    
    res = requests.post(
        url=f"{API_BASE_URL}/api/sanctions/ofac/search",
        json={"filters": filters},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

@mcp.tool()
def fuzzy_search_ofac(q: str) -> dict:
    """Perform fuzzy text matching across the OFAC sanctions database for names, addresses, and related fields.
    
    Args:
        q: Fuzzy search query for broad text matching (e.g. bank corporation)
    
    Cost: 100 credits
    """
    apikey = check_apikey()
    res = requests.get(
        url=f"{API_BASE_URL}/api/sanctions/ofac/search/fuzzy",
        params={"q": q},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

@mcp.tool()
def screen_global_sanctions_address(address: str, dataset: str = "global") -> dict:
    """Check whether a blockchain address appears on international sanctions lists from multiple countries and organizations.
    
    Args:
        address: Blockchain address to screen (e.g. 0x7FF9cFad3877F21d41Da833E2F775dB0569eE3D9)
        dataset: Global sanctions dataset to search in (global, au, ca, ch, eu, gb, il, jp, un, za, zm). Default: global
    
    Cost: 10 credits
    """
    apikey = check_apikey()
    res = requests.get(
        url=f"{API_BASE_URL}/api/sanctions/global/address",
        params={"dataset": dataset, "address": address},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

@mcp.tool()
def search_global_sanctions(
    dataset: str = "global",
    type: Optional[str] = None,
    name: Optional[str] = None,
    address: Optional[str] = None,
    country: Optional[str] = None,
    birth_date: Optional[str] = None,
    legal_form: Optional[str] = None,
    registration_number: Optional[str] = None,
    incorporation_date: Optional[str] = None,
    jurisdiction: Optional[str] = None,
    wallet: Optional[str] = None
) -> dict:
    """Search international sanctions databases using exact field matching across multiple jurisdictions.
    
    Args:
        dataset: Global sanctions dataset to search in (global, au, ca, ch, eu, gb, il, jp, un, za, zm). Default: global
        type: Entity type (individual, entity, vessel, aircraft)
        name: Entity name
        address: Physical address
        country: Country or nationality
        birth_date: Date of birth
        legal_form: Legal entity type
        registration_number: Registration number
        incorporation_date: Incorporation date
        jurisdiction: Incorporation jurisdiction
        wallet: Cryptocurrency wallet addresses
    
    Cost: 20 credits
    """
    apikey = check_apikey()
    filters = {}
    if type: filters["type"] = type
    if name: filters["name"] = name
    if address: filters["address"] = address
    if country: filters["country"] = country
    if birth_date: filters["birth_date"] = birth_date
    if legal_form: filters["legal_form"] = legal_form
    if registration_number: filters["registration_number"] = registration_number
    if incorporation_date: filters["incorporation_date"] = incorporation_date
    if jurisdiction: filters["jurisdiction"] = jurisdiction
    if wallet: filters["wallet"] = wallet
    
    res = requests.post(
        url=f"{API_BASE_URL}/api/sanctions/global/search",
        json={"dataset": dataset, "filters": filters},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

@mcp.tool()
def fuzzy_search_global_sanctions(q: str, dataset: str = "global") -> dict:
    """Perform fuzzy text matching across international sanctions databases for broader and more comprehensive coverage.
    
    Args:
        q: Fuzzy search query (e.g. Kesklinna)
        dataset: Global sanctions dataset to search in (global, au, ca, ch, eu, gb, il, jp, un, za, zm). Default: global
    
    Cost: 200 credits
    """
    apikey = check_apikey()
    res = requests.get(
        url=f"{API_BASE_URL}/api/sanctions/global/search/fuzzy",
        params={"dataset": dataset, "q": q},
        headers={"X-API-KEY": apikey}
    )
    return res.json()

# ============================================================================
# INSIGHTS APIs
# ============================================================================

@mcp.tool()
def get_crypto_news(query: Optional[str] = None, category: Optional[str] = None) -> dict:
    """Retrieve cryptocurrency and blockchain-related news and market information from multiple sources.
    
    Args:
        query: Search query for cryptocurrency news (e.g. bitcoin price)
        category: News category filter (general, bitcoin, ethereum, defi, nft, regulation, exchange, mining)
    
    Cost: 20 credits
    """
    apikey = check_apikey()
    params = {}
    if query: params["query"] = query
    if category: params["category"] = category
    
    res = requests.get(
        url=f"{API_BASE_URL}/api/insights/feeds/news",
        params=params,
        headers={"X-API-KEY": apikey}
    )
    return res.json()

def check_apikey():
    if remote:
        apikey = get_http_headers().get("x-api-key", "")
    else:
        apikey = anchain_apikey
    
    if not apikey:
            raise ValidationError("no anchain apikey provided")
    return apikey

def main():
    parser = argparse.ArgumentParser()

    # Mode selection
    parser.add_argument('--rm', '--remote', action='store_true', 
                       help='Run in remote mode')

    # http server arguments
    remote_group = parser.add_argument_group('http server options')
    remote_group.add_argument('--port', type=int, default=8002,
                             help='Port for remote mcp server (default: 8002)')
    remote_group.add_argument('--host', default='127.0.0.1',
                             help='Host for remote mcp server (default: 127.0.0.1)')

    # stdio server arguments  
    local_group = parser.add_argument_group('stdio server options')
    local_group.add_argument('-k', '--ANCHAIN_APIKEY', dest='apikey',
                            help='API key for stdio server')

    args = parser.parse_args()

    if args.rm:
        global remote
        remote = True
        mcp.run(transport="http", host=args.host, port=args.port)
    else:
        global anchain_apikey
        if args.apikey:
            anchain_apikey = args.apikey
        else:
            anchain_apikey = os.environ.get("ANCHAIN_APIKEY")
    
        if not anchain_apikey:
            print('ANCHAIN_APIKEY environment variable is required', file=sys.stderr, flush=True)
            raise ValueError('ANCHAIN_APIKEY environment variable is required')
    
        mcp.run()

if __name__ == '__main__':
    main()


