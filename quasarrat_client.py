#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

import sys
import hmac
import time
import socket
import random
import hashlib
import argparse
import binascii
import threading
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
SERVER = "127.0.0.1"
# Server listen port
PORT = 443
# AES Block size
BLOCK_SIZE = 16
# Thread counts
COUNT = 1

parser = argparse.ArgumentParser(description="QuasarRAT panel scanner.")
parser.add_argument("-k", "--key", dest="key", action="store", type=str, metavar="KEY",
                    help="Encryption or decryption key.")
parser.add_argument("-a", "--authkey", dest="authkey", action="store", type=str, metavar="AUTHKEY",
                    help="Authkey. (Base64 data)")
parser.add_argument("--apt10", action="store_true", default=False,
                    help="Customized APT10 mode.")
parser.add_argument("-s", "--server", dest="server", action="store", type=str, metavar="SERVER",
                    help="Server IP address. (default: 127.0.0.1)")
parser.add_argument("-p", "--port", dest="port", action="store", type=int, metavar="PORT",
                    help="Server port. (default: 443)")
parser.add_argument("-t", "--TAG", dest="tag", action="store", type=str, metavar="TAG",
                    help="Tag value.")
parser.add_argument("-c", "--count", dest="count", action="store", type=int, metavar="COUNT",
                    help="Scan count. (Default: 1)")
args = parser.parse_args()

if args.server:
    SERVER = args.server

if args.port:
    PORT = args.port

if args.count:
    COUNT = args.count

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

WORDS = [
    b"Argentina",
    b"Australia",
    b"Brazil",
    b"Canada",
    b"China",
    b"Frence",
    b"Germany",
    b"India",
    b"Indonesia",
    b"Italy",
    b"Japan",
    b"Mexico",
    b"Russia",
    b"SaudiArabia",
    b"SouthAfrica",
    b"SouthKorea",
    b"Turkey",
    b"UnitedKingdom",
    b"UnitedState"
]

OS = [
    b"Windows 10 Enterprise 64 Bit",
    b"Windows 8 Enterprise 64 Bit",
    b"Windows 7 32 Bit",
    b"WIndows XP 32 Bit",
    b"Linux",
    b"macOS",
    b"Android",
    b"iOS"
]

def create_packet(senddata):
    if args.apt10:
        command = [k for k, v in COMMAND_SET_APT10.items() if "GetAuthenticationResponse" in v][0] + 1
    else:
        command = [k for k, v in COMMAND_SET.items() if "GetAuthenticationResponse" in v][0] + 1

    packet = pack("B", command)
    for _, value in senddata.items():
        if len(value) != 0:
            packet += pack("B", len(value) + 1)
            packet += pack("B", len(value))
            packet += value
        else:
            packet += b"\x00"

    return packet


def quasar_connect(key, authkey, xorkey, mode):
    if args.apt10:
        commands = COMMAND_SET_APT10
    else:
        commands = COMMAND_SET

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print("[+] Connect port {0}:{1}.".format(SERVER, PORT))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        s.connect((SERVER, PORT))

        while True:
            recv_data = s.recv(1024)

            if recv_data:
                print("[+] Get data size: {0}".format(len(recv_data)))
                decode_data = decode(recv_data, key, authkey, xorkey, mode)
                print("[+] Command: {0}".format(commands[decode_data[0] - 1]))
                print("[+] Decoded data: {0}".format(decode_data))

                if commands[decode_data[0] - 1] in "GetAuthentication":
                    rand = []
                    for i in range(4):
                        rand.append(random.randint(0, len(WORDS) - 1))

                    id = hashlib.sha256(WORDS[rand[0]] + WORDS[rand[1]] + WORDS[rand[2]] + WORDS[rand[3]]).hexdigest().encode("utf-8")

                    senddata_list = {
                        "AccountType": WORDS[rand[0]],
                        "City": b"Unknown",
                        "CountryCode": b"Unknown",
                        "Country": WORDS[rand[1]],
                        "ID": id,
                        "ImageIndex": b"",
                        "OS": OS[random.randint(0, len(OS) - 1)],
                        "Pcname": WORDS[rand[2]],
                        "Region": b"Unknown",
                        "Tag": args.tag.encode("UTF-8"),
                        "User": WORDS[rand[3]],
                        "Version": b"1.3.0.0"}

                    packet = create_packet(senddata_list)

                    result = encode(packet, key, authkey, xorkey, mode)

                    s.send(result)
                    print("[+] Send data.")
                    print("[+] Send data size: {0}".format(len(result)))

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

    if not args.authkey:
        sys.exit("[!] Please set option -a (authkey).")

    if not args.tag:
        sys.exit("[!] Please set option -t (tag value).")

    key = b64decode(args.key)
    authkey = b64decode(args.authkey)
    xorkey = args.key[:4]

    if args.apt10:
        print("[+] APT10 mode.")
        mode = AES.MODE_CFB
    else:
        mode = AES.MODE_CBC

    threads = []
    print("[+] Thread count {0}.".format(COUNT))
    for _ in range(COUNT):
        th = threading.Thread(target=quasar_connect, name="th", args=(key, authkey, xorkey, mode), daemon=True)
        th.start()
        threads.append(th)
        time.sleep(1)

    for thread in threads:
        thread.join()

    #quasar_connect(key, authkey, xorkey, mode)


if __name__ == "__main__":
    main()
