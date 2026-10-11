"""
Blockchain transaction lookup for extracted wallet addresses.
Queries free APIs to get transaction history and connected addresses.

Supports: Bitcoin (BlockCypher), Ethereum (Etherscan)
Monero: privacy coin, no public lookup possible
"""

import asyncio
import aiohttp
import logging
import uuid
from typing import Optional, Any
from datetime import datetime, timezone

import pacing
from sources import http_pool
from sources.enrichment_allowlist import (
    is_enrichment_source_enabled,
    validate_enrichment_allowlist,
)
from db.models import Entity, EntityRelationship, RelationshipType
from db.queries import upsert_entity_canonical

logger = logging.getLogger(__name__)

BLOCKCYPHER_BASE = "https://api.blockcypher.com/v1/btc/main"
ETHERSCAN_BASE = "https://api.etherscan.io/api"

# Reasonable caps to avoid hammering free APIs
MAX_TRANSACTIONS_PER_WALLET = 50
MAX_CONNECTED_ADDRESSES = 10  # How many counterparty addresses to extract

# Inter-wallet pacing.  One constant covers both providers, so it has to satisfy
# whichever is stricter per-request (verified 2026-07-29):
#
#   BlockCypher free tier — 3 req/s AND 100 req/hr
#   Etherscan free key    — 5 calls/s, 100,000 calls/day
#
# 0.4 s = 2.5 req/s, inside BlockCypher's 3/s.  Provider-dictated, so it goes
# through pacing.scale_delay_floor() and no profile may shorten it.
#
# CAVEAT: BlockCypher's 100 req/hr is the binding constraint in practice and a
# per-request delay says nothing about it — 2.5 req/s exhausts the hour's
# allowance in 40 seconds.  That is an hourly budget (pattern 1 in
# docs/BACKLOG.md); MAX_CONNECTED_ADDRESSES bounds a single run but not a day.
WALLET_REQUEST_DELAY = 0.4

# Entity type constants to match extractor/regex_patterns.py
BITCOIN_ADDRESS = "BITCOIN_ADDRESS"
ETHEREUM_ADDRESS = "ETHEREUM_ADDRESS"
MONERO_ADDRESS = "MONERO_ADDRESS"


def detect_wallet_type(address: str) -> Optional[str]:
    """
    Detect cryptocurrency type from address format.
    
    Returns: BITCOIN_ADDRESS, ETHEREUM_ADDRESS, MONERO_ADDRESS, or None
    """
    address = address.strip()
    
    # Bitcoin: starts with 1, 3, or bc1
    if address.startswith(("1", "3")) and 25 <= len(address) <= 34:
        return BITCOIN_ADDRESS
    if address.startswith("bc1") and len(address) >= 42:
        return BITCOIN_ADDRESS
    
    # Ethereum: 0x prefix, 42 chars total
    if address.startswith("0x") and len(address) == 42:
        return ETHEREUM_ADDRESS
    
    # Monero: starts with 4, 95-106 chars
    if address.startswith("4") and 95 <= len(address) <= 106:
        return MONERO_ADDRESS
    
    return None


async def lookup_bitcoin_address(
    address: str,
    api_token: str = "",
) -> dict:
    """
    Look up Bitcoin address via BlockCypher API.
    
    Returns dict with financial metadata and connected addresses.
    """
    result = {
        "address": address,
        "wallet_type": BITCOIN_ADDRESS,
        "total_received_btc": 0.0,
        "total_sent_btc": 0.0,
        "balance_btc": 0.0,
        "transaction_count": 0,
        "first_seen": None,
        "last_seen": None,
        "connected_addresses": [],
        "lookup_successful": False,
        "error": None,
    }
    
    # VOIDACCESS_ENRICHMENT_SOURCES gate: no network call when disabled.
    if not is_enrichment_source_enabled("blockcypher"):
        result["error"] = "source_disabled"
        return result

    params = {"limit": MAX_TRANSACTIONS_PER_WALLET}
    if api_token:
        params["token"] = api_token
    
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with http_pool.clearnet_session() as session:
            url = f"{BLOCKCYPHER_BASE}/addrs/{address}"
            async with session.get(url, params=params, timeout=timeout) as resp:
                
                if resp.status == 429:
                    logger.warning(f"BlockCypher rate limited for {address[:12]}...")
                    result["error"] = "rate_limited"
                    return result
                
                if resp.status == 404:
                    # Valid address with no transactions
                    result["lookup_successful"] = True
                    result["error"] = "no_transactions"
                    return result
                
                if resp.status != 200:
                    result["error"] = f"http_{resp.status}"
                    return result
                
                data = await resp.json()
                
                # Satoshis to BTC conversion
                sat_to_btc = 1 / 100_000_000
                
                result["total_received_btc"] = data.get("total_received", 0) * sat_to_btc
                result["total_sent_btc"] = data.get("total_sent", 0) * sat_to_btc
                result["balance_btc"] = data.get("final_balance", 0) * sat_to_btc
                result["transaction_count"] = data.get("n_tx", 0)
                result["lookup_successful"] = True
                
                # Extract connected addresses from transaction refs
                txrefs = data.get("txrefs", []) + data.get("unconfirmed_txrefs", [])
                
                # Sort by time to get first/last seen
                confirmed_txs = [t for t in txrefs if t.get("confirmed")]
                if confirmed_txs:
                    times = [t.get("confirmed") for t in confirmed_txs if t.get("confirmed")]
                    if times:
                        result["first_seen"] = min(times)
                        result["last_seen"] = max(times)
                
                # Extract counterparty addresses from inputs/outputs
                # BlockCypher address endpoint gives txrefs but not full tx details
                # We mark incoming as FUNDED_BY, outgoing as PAID_TO
                connected = {}
                for tx in txrefs[:MAX_TRANSACTIONS_PER_WALLET]:
                    value_btc = tx.get("value", 0) * sat_to_btc
                    tx_hash = tx.get("tx_hash", "")
                    
                    # tx_input_n >= 0 means this address was an input (sending)
                    if tx.get("tx_input_n", -1) >= 0:
                        direction = "sent"  # We sent to someone
                    else:
                        direction = "received"  # Someone sent to us
                    
                    # Note: Getting actual counterparty addresses requires
                    # fetching the full transaction. For free tier, we'll simple-link
                    if value_btc > 0.001 and tx_hash:  # Only significant transactions
                        connected[tx_hash] = {
                            "direction": direction,
                            "amount": round(value_btc, 8),
                            "tx_hash": tx_hash,
                            "confirmed": tx.get("confirmed", ""),
                        }
                
                result["connected_addresses"] = list(connected.values())[:MAX_CONNECTED_ADDRESSES]
    
    except asyncio.TimeoutError:
        result["error"] = "timeout"
        logger.warning(f"BlockCypher timeout for {address[:12]}...")
    except Exception as e:
        result["error"] = str(e)[:100]
        logger.warning(f"BlockCypher lookup failed for {address[:12]}...: {e}")
    
    return result


async def lookup_ethereum_address(
    address: str,
    api_key: str = "",
) -> dict:
    """
    Look up Ethereum address via Etherscan API.
    """
    result = {
        "address": address,
        "wallet_type": ETHEREUM_ADDRESS,
        "balance_eth": 0.0,
        "transaction_count": 0,
        "first_seen": None,
        "last_seen": None,
        "connected_addresses": [],
        "lookup_successful": False,
        "error": None,
    }
    
    if not is_enrichment_source_enabled("etherscan"):
        result["error"] = "source_disabled"
        return result

    if not api_key:
        result["error"] = "no_api_key"
        return result
    
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with http_pool.clearnet_session() as session:

            # Get balance
            async with session.get(
                ETHERSCAN_BASE,
                params={
                    "module": "account",
                    "action": "balance",
                    "address": address,
                    "tag": "latest",
                    "apikey": api_key,
                },
                timeout=timeout,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "1":
                        wei_to_eth = 1 / 10**18
                        result["balance_eth"] = int(data.get("result", 0)) * wei_to_eth
            
            # Get transactions
            async with session.get(
                ETHERSCAN_BASE,
                params={
                    "module": "account",
                    "action": "txlist",
                    "address": address,
                    "startblock": 0,
                    "endblock": 99999999,
                    "page": 1,
                    "offset": MAX_TRANSACTIONS_PER_WALLET,
                    "sort": "desc",
                    "apikey": api_key,
                },
                timeout=timeout,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "1":
                        txs = data.get("result", [])
                        result["transaction_count"] = len(txs)
                        result["lookup_successful"] = True
                        
                        wei_to_eth = 1 / 10**18
                        connected = []
                        
                        for tx in txs:
                            is_incoming = tx.get("to", "").lower() == address.lower()
                            counterparty = tx.get("from") if is_incoming else tx.get("to")
                            value_eth = int(tx.get("value", 0)) * wei_to_eth
                            
                            if counterparty and counterparty.lower() != address.lower() and value_eth > 0.001:
                                connected.append({
                                    "address": counterparty,
                                    "direction": "received" if is_incoming else "sent",
                                    "amount": round(value_eth, 6),
                                    "tx_hash": tx.get("hash", ""),
                                    "confirmed": tx.get("timeStamp", ""),
                                })
                        
                        result["connected_addresses"] = connected[:MAX_CONNECTED_ADDRESSES]
                        
                        if txs:
                            # Sorted desc, so first is newest
                            result["last_seen"] = txs[0].get("timeStamp", "")
                            result["first_seen"] = txs[-1].get("timeStamp", "")
    
    except asyncio.TimeoutError:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)[:100]
        logger.warning(f"Etherscan lookup failed for {address[:12]}...: {e}")
    
    return result


async def lookup_wallet(
    address: str,
    blockcypher_token: str = "",
    etherscan_key: str = "",
) -> dict:
    """
    Unified wallet lookup. Detects type and routes to correct API.
    """
    wallet_type = detect_wallet_type(address)
    
    if wallet_type == BITCOIN_ADDRESS:
        return await lookup_bitcoin_address(address, blockcypher_token)
    elif wallet_type == ETHEREUM_ADDRESS:
        return await lookup_ethereum_address(address, etherscan_key)
    elif wallet_type == MONERO_ADDRESS:
        return {
            "address": address,
            "wallet_type": MONERO_ADDRESS,
            "lookup_successful": False,
            "error": "monero_privacy_coin",
            "note": "Monero transactions are private and cannot be looked up without view key",
        }
    else:
        return {
            "address": address,
            "wallet_type": "unknown",
            "lookup_successful": False,
            "error": "unrecognized_format",
        }


async def enrich_wallets_for_investigation(
    investigation_id: uuid.UUID,
    session: Any,
    blockcypher_token: str = "",
    etherscan_key: str = "",
    max_wallets: int = 10,
) -> dict:
    """
    For all crypto wallet entities in an investigation:
    1. Look up transaction data from blockchain APIs
    2. Store transaction metadata on the entity
    3. Create connected address entities and PAID_TO/FUNDED_BY relationships
    """
    validate_enrichment_allowlist()  # unknown ids fail loudly, never silently

    stats = {
        "wallets_looked_up": 0,
        "successful_lookups": 0,
        "edges_created": 0,
        "connected_wallets_found": 0,
        "errors": 0,
    }
    
    # Get all wallet entities for this investigation
    wallets = (
        session.query(Entity)
        .filter(
            Entity.investigation_id == investigation_id,
            Entity.entity_type.in_([BITCOIN_ADDRESS, ETHEREUM_ADDRESS, MONERO_ADDRESS]),
            Entity.value.isnot(None),
        )
        .limit(max_wallets)
        .all()
    )
    
    if not wallets:
        return stats
    
    logger.warning(f"Blockchain enrichment: {len(wallets)} wallets to process")
    
    for wallet_entity in wallets:
        address = wallet_entity.value.strip()
        stats["wallets_looked_up"] += 1
        
        try:
            lookup_result = await lookup_wallet(
                address=address,
                blockcypher_token=blockcypher_token,
                etherscan_key=etherscan_key,
            )
            
            if not lookup_result.get("lookup_successful"):
                if lookup_result.get("error") != "monero_privacy_coin":
                    stats["errors"] += 1
                continue
            
            stats["successful_lookups"] += 1
            
            # Update entity historical_context with financial summary
            wallet_type = lookup_result.get("wallet_type", "")
            tx_count = lookup_result.get("transaction_count", 0)
            
            if wallet_type == BITCOIN_ADDRESS:
                balance = lookup_result.get("balance_btc", 0)
                summary = f"BTC Balance: {balance:.4f} BTC, Transactions: {tx_count}"
            else:
                balance = lookup_result.get("balance_eth", 0)
                summary = f"ETH Balance: {balance:.4f} ETH, Transactions: {tx_count}"
            
            if not wallet_entity.historical_context:
                wallet_entity.historical_context = summary
            
            # Update first_seen if available
            first_seen_val = lookup_result.get("first_seen")
            if first_seen_val and not wallet_entity.first_seen:
                try:
                    if isinstance(first_seen_val, int) or (isinstance(first_seen_val, str) and first_seen_val.isdigit()):
                        wallet_entity.first_seen = datetime.fromtimestamp(int(first_seen_val), tz=timezone.utc)
                    elif isinstance(first_seen_val, str):
                        # BlockCypher ISO format
                        wallet_entity.first_seen = datetime.fromisoformat(first_seen_val.replace("Z", "+00:00"))
                except Exception:
                    pass
            
            # Process connected addresses
            connected = lookup_result.get("connected_addresses", [])
            for conn in connected:
                conn_address = conn.get("address")
                if not conn_address or conn_address.lower() == address.lower():
                    continue
                
                # Detect type for counterparty
                conn_type = detect_wallet_type(conn_address) or wallet_type
                
                # Create counterparty entity
                conn_entity, _ = upsert_entity_canonical(
                    session=session,
                    investigation_id=investigation_id,
                    entity_type=conn_type,
                    entity_value=conn_address,
                    confidence=0.95,
                    context_snippet=f"Related to {address[:12]} via blockchain transaction",
                    extraction_method="blockchain_api",
                )
                stats["connected_wallets_found"] += 1
                
                # Build Relationship
                direction = conn.get("direction", "sent")
                if direction == "received":
                    # conn -> us (FUNDED_BY) or conn PAID_TO us
                    source_id = conn_entity.id
                    target_id = wallet_entity.id
                else:
                    # us -> conn (PAID_TO)
                    source_id = wallet_entity.id
                    target_id = conn_entity.id
                
                # Check duplication
                existing = session.query(EntityRelationship).filter_by(
                    entity_a_id=source_id,
                    entity_b_id=target_id,
                    relationship_type=RelationshipType.PAID_TO.value
                ).first()
                
                if not existing:
                    rel = EntityRelationship(
                        entity_a_id=source_id,
                        entity_b_id=target_id,
                        relationship_type=RelationshipType.PAID_TO.value,
                        confidence=0.95,
                        metadata_json={
                            "amount": conn.get("amount"),
                            "currency": "BTC" if wallet_type == BITCOIN_ADDRESS else "ETH",
                            "tx_hash": conn.get("tx_hash"),
                        } if hasattr(EntityRelationship, "metadata_json") else None
                    )
                    session.add(rel)
                    stats["edges_created"] += 1
            
            session.flush()
            
        except Exception as e:
            stats["errors"] += 1
            logger.warning(f"Wallet enrichment failed for {address[:12]}: {e}")
        
        # Respect rate limits
        await asyncio.sleep(pacing.scale_delay_floor(WALLET_REQUEST_DELAY))
        
    session.commit()
    return stats
