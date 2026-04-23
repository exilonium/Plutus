# Plutus Bitcoin Brute Forcer
# Made by Isaac Delly
# https://github.com/Isaacdelly/Plutus
# Optimized for Render.com by Claude

from coincurve import PrivateKey as CCPrivateKey, PublicKey as CCPublicKey
import multiprocessing
from multiprocessing import Value
import hashlib
import binascii
import os
import sys
import time
import signal
import argparse
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# ── Health endpoint (silent, zero console output) ───────────────────────────────


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # suppress all request logs


def start_health_server():
    port = int(os.environ.get("PORT", 10000))
    server = HTTPServer(("0.0.0.0", port), _HealthHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


# ── Config ──────────────────────────────────────────────────────────────────────
DATABASE = os.environ.get("DATABASE_PATH", r"database/12_26_2025/")
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
HEARTBEAT = int(os.environ.get("HEARTBEAT_SECS", "60"))

# secp256k1 curve order
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Pre-compute G as a public key (private key = 1) for point-addition shortcut
GENERATOR_PUBLIC_KEY = CCPrivateKey(int(1).to_bytes(32, "big")).public_key


# ── Bloom filter ────────────────────────────────────────────────────────────────


class BloomFilter:
    def __init__(self, size_in_mb: int = 256, hash_count: int = 8):
        self.size = size_in_mb * 1024 * 1024 * 8
        self.bit_array = bytearray(self.size // 8)
        self.hash_count = hash_count

    def _get_indices(self, string: str):
        encoded = string.encode()
        indices = []
        for seed in range(self.hash_count):
            h = hashlib.sha256(seed.to_bytes(4, "big") + encoded).digest()
            val = int.from_bytes(h[:4], "big")
            indices.append(val % self.size)
        return indices

    def add(self, string: str):
        for index in self._get_indices(string):
            self.bit_array[index // 8] |= 1 << (index % 8)

    def __contains__(self, string: str) -> bool:
        for index in self._get_indices(string):
            if not (self.bit_array[index // 8] & (1 << (index % 8))):
                return False
        return True


# ── Crypto helpers ──────────────────────────────────────────────────────────────


def generate_private_key() -> str:
    return binascii.hexlify(os.urandom(32)).decode("utf-8").upper()


def private_key_to_public_key(private_key_hex: str) -> bytes:
    pk = CCPrivateKey(bytes.fromhex(private_key_hex))
    return pk.public_key.format(compressed=True)


def public_key_to_address(public_key_bytes: bytes) -> str:
    sha256_bpk = hashlib.sha256(public_key_bytes).digest()
    ripemd160_bpk = hashlib.new("ripemd160", sha256_bpk).digest()
    payload = b"\x00" + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    address_bytes = payload + checksum
    value = int.from_bytes(address_bytes, "big")
    output = []
    while value > 0:
        value, remainder = divmod(value, 58)
        output.append(ALPHABET[remainder])
    for byte in address_bytes:
        if byte == 0:
            output.append(ALPHABET[0])
        else:
            break
    return "".join(output[::-1])


def private_key_to_wif(private_key_hex: str, compressed: bool = True) -> str:
    extended_key = b"\x80" + binascii.unhexlify(private_key_hex)
    if compressed:
        extended_key += b"\x01"
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    final_key = extended_key + checksum
    value = int.from_bytes(final_key, "big")
    output = []
    while value > 0:
        value, remainder = divmod(value, 58)
        output.append(ALPHABET[remainder])
    for byte in final_key:
        if byte == 0:
            output.append(ALPHABET[0])
        else:
            break
    return "".join(output[::-1])


# ── Match handler ───────────────────────────────────────────────────────────────


def notify_match(address: str, private_key_hex: str, wif: str, public_key_hex: str):
    try:
        from notifier import notify_match_concurrent

        notify_match_concurrent(address, private_key_hex, wif, public_key_hex)
    except ImportError:
        pass
    except Exception as exc:
        print(f"[notifier] error: {exc}", flush=True)


# ── Worker process ──────────────────────────────────────────────────────────────


def main(database: BloomFilter, args: dict, counter: Value):
    # Load addresses into a fast set for exact-match verification
    fast_db: set = set()
    try:
        for filename in os.listdir(DATABASE):
            fp = os.path.join(DATABASE, filename)
            with open(fp) as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("1"):
                        fast_db.add(line)
    except Exception as exc:
        print(f"[worker] failed to load fast_db: {exc}", flush=True)

    local_counter = 0

    private_key_int = int.from_bytes(os.urandom(32), "big") % SECP256K1_ORDER
    if private_key_int == 0:
        private_key_int = 1

    current_key = CCPrivateKey(private_key_int.to_bytes(32, "big"))
    current_pub_key = current_key.public_key

    def _flush_and_exit(sig, frame):
        with counter.get_lock():
            counter.value += local_counter
        sys.exit(0)

    signal.signal(signal.SIGTERM, _flush_and_exit)

    while True:
        public_key_bytes = current_pub_key.format(compressed=True)
        address = public_key_to_address(public_key_bytes)

        if args.get("verbose"):
            print(address, flush=True)
        else:
            local_counter += 1
            if local_counter >= 1000:
                with counter.get_lock():
                    counter.value += local_counter
                local_counter = 0

        if address in database:
            if address in fast_db:
                private_key_hex = hex(private_key_int)[2:].zfill(64).upper()
                wif = private_key_to_wif(private_key_hex, compressed=True)
                pub_hex = public_key_bytes.hex().upper()

                try:
                    with open("plutus.txt", "a") as plutus:
                        plutus.write(
                            f"hex private key: {private_key_hex}\n"
                            f"WIF private key: {wif}\n"
                            f"public key:      {pub_hex}\n"
                            f"address:         {address}\n\n"
                        )
                except Exception as exc:
                    print(f"[worker] failed to write plutus.txt: {exc}", flush=True)

                print(f"FOUND: {address}", flush=True)
                notify_match(address, private_key_hex, wif, pub_hex)

        current_pub_key = CCPublicKey.combine_keys(
            [current_pub_key, GENERATOR_PUBLIC_KEY]
        )
        private_key_int = (private_key_int + 1) % SECP256K1_ORDER
        if private_key_int == 0:
            private_key_int = 1


# ── Utility modes ───────────────────────────────────────────────────────────────


def timer():
    start = time.time()
    pk_bytes = private_key_to_public_key(generate_private_key())
    public_key_to_address(pk_bytes)
    duration = time.time() - start
    print(f"Time to generate one address: {duration:.6f} seconds")
    print(f"Estimated speed per core:     {1 / duration:.2f} keys/second")
    sys.exit(0)


def test():
    hex_pk = "0000000000000000000000000000000000000000000000000000000000000001"
    expected_wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    expected_pub_hex = (
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    )
    expected_address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"

    print(f"Testing with private key: {hex_pk}\n")

    generated_wif = private_key_to_wif(hex_pk, compressed=True)
    print(f"WIF:     {generated_wif}")
    print(
        "WIF Check:",
        "PASS" if generated_wif == expected_wif else f"FAIL (expected {expected_wif})",
    )

    pub_bytes = private_key_to_public_key(hex_pk)
    gen_pub = pub_bytes.hex().upper()
    print(f"\nPubKey:  {gen_pub}")
    print(
        "PubKey Check:",
        "PASS"
        if gen_pub == expected_pub_hex
        else f"FAIL (expected {expected_pub_hex})",
    )

    gen_addr = public_key_to_address(pub_bytes)
    print(f"\nAddress: {gen_addr}")
    print(
        "Address Check:",
        "PASS"
        if gen_addr == expected_address
        else f"FAIL (expected {expected_address})",
    )

    sys.exit(0)


# ── Entry point ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    start_health_server()

    default_cpu_count = max(1, multiprocessing.cpu_count() - 1)
    default_cpu_count = int(os.environ.get("WORKER_COUNT", default_cpu_count))

    parser = argparse.ArgumentParser(
        description="Plutus Bitcoin Brute Forcer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 plutus.py                   # Run with default settings
  python3 plutus.py -v 1              # Run with verbose output
  python3 plutus.py --cpu-count 4     # Run with 4 CPU cores
  python3 plutus.py time              # Run speed test
  python3 plutus.py test              # Run brute-force logic test

Render.com environment variables:
  DATABASE_PATH   Path to address database directory
  WORKER_COUNT    Number of worker processes
  VERBOSE         Set to 1 for verbose output
  HEARTBEAT_SECS  Seconds between heartbeat log lines (default 60)
  PORT            Health server port (default 10000)
        """,
    )
    parser.add_argument(
        "action",
        nargs="?",
        default="run",
        choices=["run", "time", "help", "test"],
        help="Action to perform",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        type=int,
        choices=[0, 1],
        default=0,
        help="Verbose output (0 or 1)",
    )
    parser.add_argument(
        "--cpu-count",
        "-c",
        type=int,
        default=default_cpu_count,
        help="Number of CPU cores to use",
    )

    args = parser.parse_args()

    if args.action == "help":
        parser.print_help()
        sys.exit(0)

    if args.action == "time":
        timer()

    if args.action == "test":
        test()

    if not (0 < args.cpu_count <= multiprocessing.cpu_count()):
        print(f"Error: cpu_count must be between 1 and {multiprocessing.cpu_count()}")
        sys.exit(-1)

    print("Reading database files...")
    database = BloomFilter(256)
    count = 0

    files = [
        f for f in os.listdir(DATABASE) if os.path.isfile(os.path.join(DATABASE, f))
    ]
    total_bytes = sum(os.path.getsize(os.path.join(DATABASE, f)) for f in files)
    bytes_read = 0

    for filename in files:
        file_path = os.path.join(DATABASE, filename)
        with open(file_path) as fh:
            for address in fh:
                address = address.strip()
                if address.startswith("1"):
                    database.add(address)
                    count += 1
        bytes_read += os.path.getsize(file_path)
        sys.stdout.write(f"\rProgress: {bytes_read / total_bytes * 100:.2f}%")
        sys.stdout.flush()

    print("DONE")
    print(f"Database size:     {count}")
    print(f"Processes spawned: {args.cpu_count}")

    args_dict = vars(args)
    counter = Value("i", 0)
    processes = []

    for _ in range(args.cpu_count):
        p = multiprocessing.Process(target=main, args=(database, args_dict, counter))
        p.start()
        processes.append(p)

    def handle_sigterm(sig, frame):
        print("\nSIGTERM received — shutting down workers...", flush=True)
        for p in processes:
            p.terminate()
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_sigterm)

    if not args.verbose:
        last_heartbeat = time.time()
        try:
            while True:
                time.sleep(1)
                with counter.get_lock():
                    rate = counter.value
                    counter.value = 0
                sys.stdout.write(f"\rSpeed: {rate} keys/sec    ")
                sys.stdout.flush()
                now = time.time()
                if now - last_heartbeat >= HEARTBEAT:
                    print(f"[heartbeat] running at {rate} keys/sec", flush=True)
                    last_heartbeat = now
        except KeyboardInterrupt:
            print("\nShutting down...", flush=True)
            for p in processes:
                p.terminate()
