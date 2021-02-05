#!/usr/bin/python3
#
# pcaplights.py - Animate Nanoleaf panels based on sniffed traffic
#
# Author: Xavier Mertens <xavier@rootshell.be>
# Copyright: GPLv3 (http://gplv3.fsf.org/)
# Feel free to use the code, but please share the changes you've made
#

import re
import hashlib 
from scapy.all import *
from nanoleafapi import Nanoleaf
from random import randrange
from optparse import OptionParser

verbose        = False
nl             = None
current_effect = None
color_filter   = False
panels         = []
flows          = []

def colorize_panel(panel):

    ''' Apply a color to the given light panel
    '''

    global panels
    global nl

    # Default random colors
    red   = randrange(255)
    green = randrange(255)
    blue  = randrange(255)

    for p in panels:
        if p['port'] == panel['port']:
            try:
                # Extract RGB colors from the panels config
                r = re.search("\((\d+),(\d+),(\d+)\)", p['color'])
                if r:
                    red   = int(r.group(1))
                    green = int(r.group(2))
                    blue  = int(r.group(3))
                break
            except:
                break

    effect_data = {
        "command": "display",
        "animName": "LivePackets",
        "animType": "custom",
        "colorType": "HSB",
        "animData": "1 %d 2 %d %d %d 0 10 0 0 0 0 1" % (panel['id'], red, green, blue),
        "palette": [],
        "loop": False
    }
    try:
        nl.write_effect(effect_data)
    except:
        print("Can't apply panel color!")
    return

def check_new_flow(pkt):

    ''' Generate a MD5 hash for the network flow and test if the flow is new
        Return TRUE if new flow
    '''

    global flows
    s = "%s/%d/%s/%d" % (pkt.src,pkt.sport,pkt.dst,pkt.dport)
    flow = hashlib.md5(s.encode()).hexdigest()
    if flow in flows:
        return(False)
    flows.append(flow)
    return(True)

def process_packet(pkt):
    global nl
    global panels
    global color_filter
    global verbose

    if (pkt.haslayer(TCP) or pkt.haslayer(UDP)) and pkt.dport < 1024:
        # Skip existing network flows
        if check_new_flow(pkt) == False:
            return

        # Search if port is already assigned to a panel
        found_panel = False
        free_panel = idx = 0
        for p in panels:
            if p['port'] == 0 and color_filter == False:
                free_panel = idx
            elif p['port'] == pkt.dport:
                found_panel = True
                colorize_panel(p)
                break
            idx += 1
        if not found_panel and color_filter == False:
            if verbose:
                sys.stderr.write("Panel ID %d assigned to port %d\n" % (free_panel, pkt.dport))
            panels[free_panel]['port'] = pkt.dport
            colorize_panel(panels[free_panel])

    return

def main(argv):
    global nl
    global current_effect
    global panels
    global ports_colors
    global color_filter

    parser = OptionParser(usage="usage: %prog [options]", version="%prog 1.0")
    parser.add_option('-i', '--interface', dest='interface', default='lo', type='string', \
    		help='Interface (default: "lo")')
    parser.add_option('-f', '--filter', dest='bpf_filter', default='ip', type='string', \
    		help='BPF Filter (default: "ip")')
    parser.add_option('-c', '--count', dest='count', default=0, type='int', \
    		help='Packets to capture (default: no limit)')
    parser.add_option('-H', '--host', dest='host', type='string', \
    		help='Nanoleaf Controller IP/FQDN')
    parser.add_option('-C', '--colors', dest='colors', type='string', \
    		help='Color for protocols (port1=(r,g,b)/port2=(r,g,b)/...) (default: random)')
    parser.add_option('-v', '--verbose', action='store_true', dest='verbose', \
                help='Verbose output')
    (options, args) = parser.parse_args()

    if options.verbose:
        verbose = True

    if options.host == None:
        print("Nanoleaf controller FQDN/IP not provided?")
        exit(1)

    if options.colors:
        color_filter = True

    try:
        nl = Nanoleaf(options.host)
    except:
        print("Can't connect to Nanoleaf device. Generate a new authentication token?")
        exit(1)

    if not nl.get_power():
        print("Turn on the Naoleaf device.")
        exit(1)

    if verbose:
        sys.stderr.write("Nanoleaf is powered on.\n")

    try:
        current_effect = nl.get_current_effect()
        if verbose:
            sys.stderr.write("Current effect: %s\n" % current_effect)
    except:
        print("Cannot get the current effect?")

    try:
        layout = nl.get_layout()
        num_panels = int(layout['numPanels']) - 1;
        panels = [dict() for x in range(num_panels)]
        if verbose:
            sys.stderr.write("Number of panels detected: %d\n" % num_panels)
    except:
        print("Can't get the panel IDs. Check network connectivity and authentication token?")
        exit(1)

    # Initialize panels
    idx = 0
    for p in layout['positionData']:
        if int(p['panelId']) > 0:
            panels[idx]['id'] = int(p['panelId'])
            panels[idx]['port'] = 0
            panels[idx]['color'] = None
        idx += 1

    # Assigned defined colors to panels   
    if options.colors:
        colors = options.colors.split("/")
        idx = 0
        for c in colors:
            r = re.search("(\d+)=(\(\d+,\d+,\d+\))", c)
            if r:
                panels[idx]['port'] = int(r.group(1))
                panels[idx]['color'] = r.group(2)
                idx += 1
            else:
                print("Skipping malformed protocol/color: %s" % c)

    try:
        sniff(iface=options.interface, filter=options.bpf_filter, prn=process_packet, count=options.count)
    except:
        print("Can't sniff packets.")
        exit(1)

    if current_effect:
        try:
            if not nl.set_effect(current_effect):
                print("Cannot restore previous effect!")
        except:
            print("Cannot restore previous effect!")

if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        print("Interrupted!")
        if current_effect:
            try:
                if not nl.set_effect(current_effect):
                    print("Cannot restore previous effect!")
            except:
                print("Cannot restore previous effect!")
        sys.exit(1)
