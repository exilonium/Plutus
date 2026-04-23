import os
import threading
import requests
import time


def _post_discord(webhook_url, payload):
    """Internal helper to post to Discord."""
    if not webhook_url or "your_webhook" in webhook_url:
        return
    try:
        discord_payload = {
            "content": f"🚀 **BTC Found!**\nAddress: `{payload['address']}`",
            "embeds": [
                {
                    "title": "Wallet Details",
                    "color": 0xF1C40F,  # Gold
                    "fields": [
                        {
                            "name": "Address",
                            "value": payload["address"],
                            "inline": False,
                        },
                        {"name": "WIF", "value": payload["wif"], "inline": False},
                        {
                            "name": "Private Key (Hex)",
                            "value": payload["private_key_hex"],
                            "inline": False,
                        },
                    ],
                    "footer": {"text": f"Found at: {payload['found_at']}"},
                }
            ],
        }
        requests.post(webhook_url, json=discord_payload, timeout=10)
    except Exception as e:
        print(f"\n[Notifier] Discord error: {e}")


def _post_supabase(url, key, table, payload):
    """Internal helper to post to Supabase REST API."""
    if not url or not key:
        return
    try:
        endpoint = f"{url}/rest/v1/{table}"
        headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
        }
        requests.post(endpoint, headers=headers, json=payload, timeout=10)
    except Exception as e:
        print(f"\n[Notifier] Supabase error: {e}")


def notify_match_concurrent(address, private_key_hex, wif, public_key_hex):
    """
    Spawns background threads to notify Discord and Supabase
    without blocking the main execution.
    """
    # Capture current time
    found_at = time.strftime("%Y-%m-%d %H:%M:%S")

    # Prepare payload
    payload = {
        "address": address,
        "private_key_hex": private_key_hex,
        "wif": wif,
        "public_key_hex": public_key_hex,
        "found_at": found_at,
    }

    # Get credentials from environment
    webhook_url = os.getenv("WEBHOOK_URL")
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")
    supabase_table = os.getenv("SUPABASE_TABLE", "wallets")

    # Start threads
    discord_thread = threading.Thread(
        target=_post_discord, args=(webhook_url, payload), daemon=True
    )
    supabase_thread = threading.Thread(
        target=_post_supabase,
        args=(supabase_url, supabase_key, supabase_table, payload),
        daemon=True,
    )

    discord_thread.start()
    supabase_thread.start()

    # Note: Threads are daemonized so they don't hang the script on exit.
    # No .join() is called so the main loop continues immediately.


if __name__ == "__main__":
    # Test block (requires env vars to be set in shell)
    print("Testing concurrent notifications...")
    notify_match_concurrent("TEST_ADDR", "TEST_HEX", "TEST_WIF", "TEST_PUB")
    print("Notifications triggered in background. Waiting 2 seconds for threads...")
    time.sleep(2)
    print("Test complete.")
