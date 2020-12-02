#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

import sys
import hmac
import hashlib
import argparse
import binascii
from struct import pack
from base64 import b64decode

try:
    from Crypto.Cipher import AES
    has_crypto = True
except ImportError:
    has_crypto = False

try:
    from pbkdf2 import PBKDF2
    has_pbkdf2 = True
except ImportError:
    has_pbkdf2 = False

try:
    import pyqlz
    has_quicklz = True
except ImportError:
    has_quicklz = False


parser = argparse.ArgumentParser(description="QuasarRAT packet decrptor.")
parser.add_argument("data", type=str, metavar="DATA", help="Packet binary data.")
parser.add_argument("-e", "--enc", action="store_true", default=False,
                    help="Encrypt packet data.")
parser.add_argument("-d", "--dec", action="store_true", default=False,
                    help="Decrypt packet data.")
parser.add_argument("-k", "--key", dest="key", action="store", type=str, metavar="KEY",
                    help="Encryption or decryption key.")
parser.add_argument("-a", "--authkey", dest="authkey", action="store", type=str, metavar="AUTHKEY",
                    help="Authkey. (Base64 data)")
parser.add_argument("--apt10", action="store_true", default=False,
                    help="Customized APT10 mode.")
args = parser.parse_args()

BLOCK_SIZE = 16

# pkcs7
def _pad(data):
    in_len = len(data)
    pad_size = BLOCK_SIZE - (in_len % BLOCK_SIZE)
    return data.ljust(in_len + pad_size, pad_size.to_bytes(1, "little"))

def decode_data(data, key, mode):
    aes_iv = data[32:48]
    cipher = AES.new(key[:16], mode, IV=aes_iv)
    result = cipher.decrypt(data[48:])

    return result

def encode_data(data, key, mode):
    salt = binascii.unhexlify(b'BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941')
    generator = PBKDF2(key, salt, 50000)
    aes_iv = generator.read(16)

    cipher = AES.new(key[:16], mode, IV=aes_iv)
    result = cipher.encrypt(_pad(data))

    return aes_iv + result

def main():
    if not has_crypto:
        sys.exit("[!] pycrypto must be installed for this script.")

    if not has_pbkdf2:
        sys.exit("[!] pbkdf2 must be installed for this script.")

    if not has_quicklz:
        sys.exit("[!] python-quicklz must be installed for this script.")

    if not args.key:
        sys.exit("[!] Please set option -k (Encryption or decryption key).")

    with open(args.data, "rb") as fb:
        data = fb.read()

    key = b64decode(args.key)
    authkey = b64decode(args.authkey)

    xorkey = args.key[:4]

    if args.apt10:
        print("[+] APT10 mode.")
        mode = AES.MODE_CFB
    else:
        mode = AES.MODE_CBC

    if args.dec:
        print("[+] Decrypt mode.")
        enc_data = data[4:]
        result = []
        if args.apt10:
            for i in range(len(enc_data)):
                result.append(pack("B", enc_data[i] ^ ord(xorkey[i % 4])))
            enc_data = b"".join(result)

        hash = hmac.new(authkey, enc_data[32:], hashlib.sha256).digest()
        enc_hash = enc_data[:32]

        if hash == enc_hash:
            print("[+] Hash check OK.")
        else:
            sys.exit("[!] This packet is corrupted.")

        result = pyqlz.decompress(decode_data(enc_data, key, mode))
        with open(args.data + ".decode", "wb") as fb:
            fb.write(result)
        print("[+] Created {0}".format(args.data + ".decode"))

    if args.enc:
        print("[+] Encrypt mode.")
        enc_data = encode_data(pyqlz.compress(data), key, mode)
        hash = hmac.new(authkey, enc_data, hashlib.sha256).digest()

        data_set = hash + enc_data
        if args.apt10:
            data_header = pack("i", len(data_set))
            with open(args.data + ".encode", "wb") as fb:
                for i in range(len(data_header)):
                    fb.write(pack("B", data_header[i] ^ ord(xorkey[i % 4])))
                for i in range(len(data_set)):
                    fb.write(pack("B", data_set[i] ^ ord(xorkey[i % 4])))
        else:
            with open(args.data + ".encode", "wb") as fb:
                fb.write(pack("i", len(data_set)) + data_set)
        print("[+] Created {0}".format(args.data + ".encode"))

if __name__ == "__main__":
    main()
