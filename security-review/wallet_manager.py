import re
import logging
import requests

logger = logging.getLogger(__name__)

# SS58 address pattern for Bittensor (starts with '5', 48 chars total, base58 alphabet)
_SS58_RE = re.compile(r"^5[1-9A-HJ-NP-Za-km-z]{47}$")


def is_valid_ss58(address: str) -> bool:
    """Return True if the address looks like a valid SS58 Bittensor wallet address."""
    if not address:
        return False
    return bool(_SS58_RE.match(address))


def fetch_wallet_staking_data(wallet: str, api_key: str) -> dict:
    """
    Fetch staking/delegation data for a wallet from the Taostats API.

    Returns a dict with keys such as:
      - total_staked (float): total TAO staked
      - active_subnets (int): number of subnets the wallet is active in
      - delegations (list): raw delegation records

    Returns an empty dict on failure.
    """
    if not api_key:
        logger.warning("fetch_wallet_staking_data: TAOSTATS_API_KEY not set.")
        return {}
    if not wallet:
        return {}

    url = "https://api.taostats.io/api/dtao/stake_balance/latest/v1"
    headers = {"Authorization": api_key, "accept": "application/json"}
    params = {"hotkey": wallet, "limit": 100}
    try:
        logger.info("Taostats staking API request for wallet=%s", wallet[:12])
        r = requests.get(url, headers=headers, params=params, timeout=15)
        logger.info("Taostats staking API response: status=%d", r.status_code)
        if r.status_code == 401:
            logger.error("Taostats staking API: 401 Unauthorized.")
            return {}
        if r.status_code == 429:
            logger.warning("Taostats staking API: 429 Rate Limit.")
            return {}
        if r.status_code != 200:
            logger.warning("Taostats staking API: unexpected status %d", r.status_code)
            return {}
        data = r.json().get("data", [])
        if not data:
            return {"total_staked": 0.0, "active_subnets": 0, "delegations": []}
        total_staked = sum(float(d.get("stake", 0)) for d in data)
        active_subnets = len({d.get("netuid") for d in data if d.get("netuid") is not None})
        return {
            "total_staked": round(total_staked, 4),
            "active_subnets": active_subnets,
            "delegations": data,
        }
    except requests.exceptions.Timeout:
        logger.warning("Taostats staking API: Timeout.")
        return {}
    except Exception as e:
        logger.error("Taostats staking API error: %s", e)
        return {}


def fetch_wallet_earnings(wallet: str, api_key: str) -> dict:
    """
    Fetch recent emission/earnings data for a wallet from the Taostats API.

    Returns a dict with:
      - total_emission (float): total emission in TAO
      - records (list): raw records
    """
    if not api_key or not wallet:
        return {}

    url = "https://api.taostats.io/api/emission/v1"
    headers = {"Authorization": api_key, "accept": "application/json"}
    params = {"hotkey": wallet, "limit": 50}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=15)
        if r.status_code != 200:
            return {}
        records = r.json().get("data", [])
        total = sum(float(rec.get("emission", 0)) for rec in records)
        return {"total_emission": round(total, 6), "records": records}
    except Exception as e:
        logger.error("Taostats earnings API error: %s", e)
        return {}
