#!/usr/bin/env python3

import sys
from scapy.all import *

# The MAC address table is a dictionnary composed of 'key-value' pairs.
mac_address_table = {}

# Switch settings can change the switch behavior.
# They are also stored in a dictionnary.
sw_settings = {
    "debug": False,
    "forwarding": True
}

def log(msg):
    if sw_settings["debug"]:
        # Print message on standard error.
        print(msg, file=sys.stderr)

def on_off(b):
    if b:
        return "on"
    else:
        return "off"

def cli():
    # Those variables must be declared as 'global' in order to
    # modify their content in a function.
    global mac_address_table
    global sw_settings

    while True:
        # Print a prompt and wait for user input.
        cmd = input("switch#")

        if cmd == "debug":
            # ^ is the exclusive OR boolean operation
            sw_settings["debug"] ^= True
            print("debug is now " + on_off(sw_settings["debug"]))
        elif cmd == "forwarding":
            sw_settings["forwarding"] ^= True
            print("forwarding is now " + on_off(sw_settings["forwarding"]))
        elif cmd == "exit":
            return
        elif cmd != "":
            print("Commande inconnue : " + cmd)

def send_frame(pkt, to_port):
    log("Sending frame to " + pkt[Ether].dst + " on port " + to_port)
    sendp(pkt, iface=to_port, verbose=0)

def flood_frame(pkt, not_to_port):
    log("Sending frame to on ALL active ports but " + not_to_port)
    for port in active_ports:
        if port != not_to_port:
            send_frame(pkt, port)
    log("Done")

def learn(mac, port):
    if not mac in mac_address_table:
        mac_address_table[mac] = port
        log("Added " + mac + " on port " + port)

def forward(eth_frame, dst, in_port):
    if not sw_settings["forwarding"]:
        return

    if dst in mac_address_table:
        out_port = mac_address_table[dst]
        send_frame(eth_frame, out_port)
    else:
        flood_frame(eth_frame, in_port)

def new_frame(eth_frame):
    # The source address of the Ethernet frame.
    src = eth_frame[Ether].src
    # Its destination address.
    dst = eth_frame[Ether].dst
    # The incoming port.
    in_port = eth_frame.sniffed_on

    learn(src, in_port)

    forward(eth_frame, dst, in_port)

# sys.argv is a list that contains the command-line arguments
# passed to the script.
# The first element (sys.argv[0]) contains the name of the script.
active_ports = sys.argv[1:]

if len(active_ports) == 0:
    print("Your switch has no port!")
    sys.exit(-1)

log("Active ports : " + str(active_ports))

# Setup a Scapy sniffer on the selected network interfaces.
# For each sniffed packet, the sniffer calls the new_frame() function.
# The sniffer does not store any packet in memory,
# therefore it can run endlessly.
# Only inbound packets will be captured (packets sent are ignored).
t = AsyncSniffer(iface=active_ports, prn=new_frame, store=0, filter="inbound")

# Start the capture
t.start()

cli()

# Stop the capture
t.stop()
