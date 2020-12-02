#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

import sys
import hmac
import socket
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

# Server IP address
SERVER = "0.0.0.0"
# Server listen port
PORT = 443
# AES Block size
BLOCK_SIZE = 16

parser = argparse.ArgumentParser(description="QuasarRAT panel.")
parser.add_argument("-k", "--key", dest="key", action="store", type=str, metavar="KEY",
                    help="Encryption or decryption key.")
parser.add_argument("-a", "--authkey", dest="authkey", action="store", type=str, metavar="AUTHKEY",
                    help="Authkey. (Base64 data)")
parser.add_argument("--apt10", action="store_true", default=False,
                    help="Customized APT10 mode.")
parser.add_argument("-s", "--server", dest="server", action="store", type=str, metavar="SERVER",
                    help="Listening Server IP address. (default: 0.0.0.0)")
parser.add_argument("-p", "--port", dest="port", action="store", type=int, metavar="PORT",
                    help="Listening Server port. (default: 443)")
parser.add_argument("-l", "--listen", action="store_true", default=False,
                    help="QuasarRAT server mode.")
args = parser.parse_args()

# Command set
COMMAND_SET_APT10 = {
    1: "DoPlugin",
    5: "DoPluginResponse",
    6: "GetConnectionsResponse",
    7: "ReverseProxyDisconnect",
    9: "ReverseProxyData",
    10: "ReverseProxyConnectResponse",
    17: "ReverseProxyConnect",
    18: "GetChangeRegistryValueResponse",
    21: "GetRenameRegistryValueResponse",
    22: "GetDeleteRegistryValueResponse",
    23: "GetCreateRegistryValueResponse",
    24: "GetRenameRegistryKeyResponse",
    25: "GetDeleteRegistryKeyResponse",
    26: "GetCreateRegistryKeyResponse",
    29: "GetRegistryKeysResponse",
    31: "DoShellExecuteResponse",
    32: "GetMonitorsResponse",
    33: "GetSystemInfoResponse",
    34: "DoDownloadFileResponse",
    35: "GetDirectoryResponse",
    37: "GetDrivesResponse",
    38: "GetProcessesResponse",
    40: "GetDesktopResponse",
    41: "SetStatusFileManager",
    42: "SetStatus",
    43: "GetAuthenticationResponse",
    44: "DoCloseConnection",
    45: "GetConnections",
    46: "SetAuthenticationSuccess",
    47: "DoChangeRegistryValue",
    48: "DoRenameRegistryValue",
    49: "DoDeleteRegistryValue",
    50: "DoCreateRegistryValue",
    51: "DoRenameRegistryKey",
    52: "DoDeleteRegistryKey",
    53: "DoCreateRegistryKey",
    54: "DoLoadRegistryKey",
    55: "DoUploadFile",
    56: "DoDownloadFileCancel",
    57: "DoPathDelete",
    59: "DoPathRename",
    60: "DoShellExecute",
    61: "GetMonitors",
    62: "GetSystemInfo",
    63: "DoKeyboardEvent",
    65: "DoMouseEvent",
    67: "DoDownloadFile",
    68: "GetDirectory",
    69: "GetDrives",
    70: "DoProcessStart",
    71: "DoProcessKill",
    72: "GetProcesses",
    73: "GetDesktop",
    74: "GetAuthentication"}

COMMAND_SET = {
    1: "GetConnectionsResponse",
    5: "ReverseProxyDisconnect",
    7: "ReverseProxyData",
    8: "ReverseProxyConnectResponse",
    13: "AddressFamily",
    15: "ReverseProxyConnect",
    16: "GetChangeRegistryValueResponse",
    19: "GetRenameRegistryValueResponse",
    20: "GetDeleteRegistryValueResponse",
    21: "GetCreateRegistryValueResponse",
    22: "GetRenameRegistryKeyResponse",
    23: "GetDeleteRegistryKeyResponse",
    24: "GetCreateRegistryKeyResponse",
    27: "GetRegistryKeysResponse",
    29: "GetPasswordsResponse",
    31: "GetKeyloggerLogsResponse",
    32: "GetStartupItemsResponse",
    33: "DoShellExecuteResponse",
    34: "GetWebcamResponse",
    35: "GetWebcamsResponse",
    42: "GetMonitorsResponse",
    43: "GetSystemInfoResponse",
    44: "DoDownloadFileResponse",
    45: "GetDirectoryResponse",
    47: "GetDrivesResponse",
    48: "GetProcessesResponse",
    50: "GetDesktopResponse",
    51: "SetUserStatus",
    53: "SetStatusFileManager",
    54: "SetStatus",
    55: "GetAuthenticationResponse",
    56: "DoCloseConnection",
    57: "GetConnections",
    58: "SetAuthenticationSuccess",
    59: "DoChangeRegistryValue",
    60: "DoRenameRegistryValue",
    61: "DoDeleteRegistryValue",
    62: "DoCreateRegistryValue",
    63: "DoRenameRegistryKey",
    64: "DoDeleteRegistryKey",
    65: "DoCreateRegistryKey",
    66: "DoLoadRegistryKey",
    67: "GetPasswords",
    68: "DoUploadFile",
    69: "GetKeyloggerLogs",
    70: "DoDownloadFileCancel",
    71: "DoStartupItemRemove",
    72: "DoStartupItemAdd",
    73: "GetStartupItems",
    74: "DoShutdownAction",
    76: "DoPathDelete",
    78: "DoPathRename",
    79: "DoShellExecute",
    80: "GetWebcam",
    81: "GetWebcams",
    82: "GetMonitors",
    83: "DoClientUpdate",
    84: "DoShowMessageBox",
    85: "DoVisitWebsite",
    86: "GetSystemInfo",
    87: "DoKeyboardEvent",
    89: "DoMouseEvent",
    91: "DoDownloadFile",
    92: "GetDirectory",
    93: "GetDrives",
    94: "DoProcessStart",
    95: "DoProcessKill",
    96: "GetProcesses",
    97: "GetDesktop",
    98: "DoUploadAndExecute",
    99: "DoDownloadAndExecute",
    100: "DoAskElevate",
    101: "DoWebcamStop",
    102: "DoClientUninstall",
    103: "DoClientReconnect",
    104: "DoClientDisconnect",
    105: "GetAuthentication"}

if args.server:
    SERVER = args.server

if args.port:
    PORT = args.port

def send_data(data, key, authkey, xorkey, mode, conn):
    if args.apt10:
        commands = COMMAND_SET_APT10
    else:
        commands = COMMAND_SET

    result = encode(data, key, authkey, xorkey, mode)
    conn.send(result)

    recv_data = conn.recv(1024)
    if recv_data:
        print("[+] Get data size: {0}".format(len(recv_data)))
        decode_data = decode(recv_data, key, authkey, xorkey, mode)
        print("[+] Command: {0}".format(commands[decode_data[0] - 1]))
        print("[+] Decoded data: {0}".format(decode_data))

def quasar_server(key, authkey, xorkey, mode):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print("[+] Listen port {0}:{1}.".format(SERVER, PORT))
        s.bind((SERVER, PORT))
        s.listen(10)
        while True:
            conn, addr = s.accept()
            print("[+] Get packet from {0}".format(addr))
            with conn:
                if args.apt10:
                    data = pack("B", 0x4B)
                else:
                    data = pack("B", 0x6A)

                send_data(data, key, authkey, xorkey, mode, conn)

                if args.apt10:
                    data = pack("B", 0x2F)
                else:
                    data = pack("B", 0x3B)

                send_data(data, key, authkey, xorkey, mode, conn)

                if args.apt10:
                    data = pack("B", 0x3F)

                    send_data(data, key, authkey, xorkey, mode, conn)

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

def decode(data, key, authkey, xorkey, mode):
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

    return result

def encode_data(data, key, mode):
    salt = binascii.unhexlify(b'BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941')
    generator = PBKDF2(key, salt, 50000)
    aes_iv = generator.read(16)

    cipher = AES.new(key[:16], mode, IV=aes_iv)
    result = cipher.encrypt(_pad(data))

    return aes_iv + result

def encode(data, key, authkey, xorkey, mode):
    enc_data = encode_data(pyqlz.compress(data), key, mode)
    hash = hmac.new(authkey, enc_data, hashlib.sha256).digest()

    data_set = hash + enc_data
    if args.apt10:
        result_list = []
        data_header = pack("i", len(data_set))
        for i in range(len(data_header)):
            result_list.append(pack("B", data_header[i] ^ ord(xorkey[i % 4])))
        for i in range(len(data_set)):
            result_list.append(pack("B", data_set[i] ^ ord(xorkey[i % 4])))
        result = b"".join(result_list)
    else:
        result = pack("i", len(data_set)) + data_set

    return result

def main():
    if not has_crypto:
        sys.exit("[!] pycrypto must be installed for this script.")

    if not has_pbkdf2:
        sys.exit("[!] pbkdf2 must be installed for this script.")

    if not has_quicklz:
        sys.exit("[!] python-quicklz must be installed for this script.")

    if not args.key:
        sys.exit("[!] Please set option -k (Encryption or decryption key).")

    key = b64decode(args.key)
    authkey = b64decode(args.authkey)
    xorkey = args.key[:4]

    if args.apt10:
        print("[+] APT10 mode.")
        mode = AES.MODE_CFB
    else:
        mode = AES.MODE_CBC

    quasar_server(key, authkey, xorkey, mode)


if __name__ == "__main__":
    main()
