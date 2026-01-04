# Plutus Bitcoin Brute Forcer
# Made by Isaac Delly
# https://github.com/Isaacdelly/Plutus

from coincurve import PrivateKey as CCPrivateKey, PublicKey as CCPublicKey
import multiprocessing
from multiprocessing import Value
import hashlib
import binascii
import os
import sys
import time
import argparse

DATABASE = r'database/12_26_2025/'
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

GENERATOR_PUBLIC_KEY = CCPrivateKey(int(1).to_bytes(32, 'big')).public_key

class BloomFilter:
    def __init__(self, size_in_mb=256):
        self.size = size_in_mb * 1024 * 1024 * 8
        self.bit_array = bytearray(self.size // 8)
        self.hash_count = 6 

    def get_indices(self, string):
        h = hashlib.sha256(string.encode()).digest()
        indices = []
        for i in range(self.hash_count):
            start = i * 4
            chunk = h[start : start + 4]
            val = int.from_bytes(chunk, 'big')
            indices.append(val % self.size)
        return indices

    def add(self, string):
        for index in self.get_indices(string):
            byte_index = index // 8
            bit_index = index % 8
            self.bit_array[byte_index] |= (1 << bit_index)

    def __contains__(self, string):
        for index in self.get_indices(string):
            byte_index = index // 8
            bit_index = index % 8
            if not (self.bit_array[byte_index] & (1 << bit_index)):
                return False
        return True

def generate_private_key():
    return binascii.hexlify(os.urandom(32)).decode('utf-8').upper()

def private_key_to_public_key(private_key):
    pk = CCPrivateKey(bytes.fromhex(private_key))
    return pk.public_key.format(compressed=True)

def public_key_to_address(public_key_bytes):
    sha256_bpk = hashlib.sha256(public_key_bytes).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    prepend_network_byte = b'\x00' + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(prepend_network_byte).digest()).digest()[:4]
    address_bytes = prepend_network_byte + checksum
    value = int.from_bytes(address_bytes, 'big')
    output = []
    while value > 0:
        value, remainder = divmod(value, 58)
        output.append(ALPHABET[remainder])
    for byte in address_bytes:
        if byte == 0: output.append(ALPHABET[0])
        else: break
    return ''.join(output[::-1])

def private_key_to_wif(private_key, compressed=True):
    extended_key = b'\x80' + binascii.unhexlify(private_key)
    if compressed:
        extended_key += b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    final_key = extended_key + checksum
    value = int.from_bytes(final_key, 'big')
    output = []
    while value > 0:
        value, remainder = divmod(value, 58)
        output.append(ALPHABET[remainder])
    for byte in final_key:
        if byte == 0: output.append(ALPHABET[0])
        else: break
    return ''.join(output[::-1])

def main(database, args, counter):
    local_counter = 0
    
    # Pick a random starting number
    private_key_int = int.from_bytes(os.urandom(32), 'big')
    
    # Calculate the initial Public Key
    current_key = CCPrivateKey(private_key_int.to_bytes(32, 'big'))
    current_pub_key = current_key.public_key

    while True:
        # Get compressed bytes for hashing
        public_key_bytes = current_pub_key.format(compressed=True)
        
        # Generate Address
        address = public_key_to_address(public_key_bytes)

        if args['verbose']:
            print(address)
        else:
            local_counter += 1
            if local_counter >= 1000:
                with counter.get_lock():
                    counter.value += local_counter
                local_counter = 0
        
        # Check Bloom Filter
        if address in database:
            # Convert our int tracker back to hex for the log/check
            private_key_hex = hex(private_key_int)[2:].zfill(64).upper()
            
            found = False
            for filename in os.listdir(DATABASE):
                with open(DATABASE + filename) as file:
                    if address in file.read():
                        found = True
                        with open('plutus.txt', 'a') as plutus:
                            plutus.write('hex private key: ' + private_key_hex + '\n' +
                                         'WIF private key: ' + str(private_key_to_wif(private_key_hex, compressed=True)) + '\n' +
                                         'public key: ' + public_key_bytes.hex().upper() + '\n' +
                                         'address: ' + str(address) + '\n\n')
                        break
            if found:
                print(f"FOUND: {address}")

        # SHORTCUT: Point Addition
        # Instead of generating a new key from scratch, we add G to the current point Pub(k+1) = Pub(k) + G
        current_pub_key = CCPublicKey.combine_keys([current_pub_key, GENERATOR_PUBLIC_KEY])
        
        # Keep our integer tracker in sync so we know the private key if we find a match
        private_key_int += 1

def timer():
    start = time.time()
    private_key = generate_private_key()
    public_key_bytes = private_key_to_public_key(private_key)
    public_key_to_address(public_key_bytes)
    end = time.time()
    duration = end - start
    print(f"Time to generate one address: {duration:.6f} seconds")
    print(f"Estimated speed per core: {1/duration:.2f} keys/second")
    sys.exit(0)

def test():
    # Hardcoded values for testing (Private Key: 1)
    hex_private_key = "0000000000000000000000000000000000000000000000000000000000000001"
    expected_wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    expected_public_key_hex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    expected_address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"

    print(f"Testing with Private Key: {hex_private_key}")

    # Test WIF Generation
    generated_wif = private_key_to_wif(hex_private_key, compressed=True)
    print(f"Generated WIF: {generated_wif}")
    if generated_wif == expected_wif:
        print("WIF Check: PASS")
    else:
        print(f"WIF Check: FAIL (Expected {expected_wif})")

    # Test Public Key Generation
    public_key_bytes = private_key_to_public_key(hex_private_key)
    generated_public_key_hex = public_key_bytes.hex().upper()
    print(f"Generated Public Key: {generated_public_key_hex}")
    if generated_public_key_hex == expected_public_key_hex:
        print("Public Key Check: PASS")
    else:
        print(f"Public Key Check: FAIL (Expected {expected_public_key_hex})")

    # Test Address Generation
    generated_address = public_key_to_address(public_key_bytes)
    print(f"Generated Address: {generated_address}")
    if generated_address == expected_address:
        print("Address Check: PASS")
    else:
        print(f"Address Check: FAIL (Expected {expected_address})")
    
    sys.exit(0)

if __name__ == '__main__':
    # Default to (CPU count - 1) to prevent system freezing, but minimum 1
    default_cpu_count = multiprocessing.cpu_count()
    if default_cpu_count > 1:
        default_cpu_count -= 1

    parser = argparse.ArgumentParser(
        description='Plutus Bitcoin Brute Forcer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 plutus.py                   # Run with default settings
  python3 plutus.py -v 1              # Run with verbose output
  python3 plutus.py --cpu-count 4     # Run with 4 CPU cores
  python3 plutus.py time              # Run speed test
  python3 plutus.py test              # Run brute-force logic test
        '''
    )
    parser.add_argument('action', nargs='?', default='run', choices=['run', 'time', 'help', 'test'], help='Action to perform')
    parser.add_argument('--verbose', '-v', type=int, choices=[0, 1], default=0, help='Verbose output (0 or 1)')
    parser.add_argument('--cpu-count', '-c', type=int, default=default_cpu_count, help='Number of CPU cores')

    args = parser.parse_args()

    if args.action == 'help':
        parser.print_help()
        sys.exit(0)

    if args.action == 'time':
        timer()

    if args.action == 'test':
        test()

    if not (0 < args.cpu_count <= multiprocessing.cpu_count()):
        print(f'Error: cpu_count must be between 1 and {multiprocessing.cpu_count()}')
        sys.exit(-1)
    
    print('reading database files...')
    database = BloomFilter(256)
    count = 0
    
    files = [f for f in os.listdir(DATABASE) if os.path.isfile(os.path.join(DATABASE, f))]
    total_bytes = sum(os.path.getsize(os.path.join(DATABASE, f)) for f in files)
    bytes_read = 0

    for filename in files:
        file_path = os.path.join(DATABASE, filename)
        with open(file_path) as file:
            for address in file:
                address = address.strip()
                if address.startswith('1'):
                    database.add(address)
                    count += 1
        
        bytes_read += os.path.getsize(file_path)
        sys.stdout.write(f"\rProgress: {bytes_read / total_bytes * 100:.2f}%")
        sys.stdout.flush()

    print('\nDONE')
    print('database size: ' + str(count))
    print('processes spawned: ' + str(args.cpu_count))
    
    args_dict = vars(args)
    counter = Value('i', 0)
    processes = []
    
    for cpu in range(args.cpu_count):
        p = multiprocessing.Process(target = main, args = (database, args_dict, counter))
        p.start()
        processes.append(p)
        
    if not args.verbose:
        try:
            while True:
                time.sleep(1)
                with counter.get_lock():
                    rate = counter.value
                    counter.value = 0
                sys.stdout.write(f"\rSpeed: {rate} keys/sec    ")
                sys.stdout.flush()
        except KeyboardInterrupt:
            print("\nShutting down...")
            for p in processes:
                p.terminate()
