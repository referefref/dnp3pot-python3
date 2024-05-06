#! /usr/bin/env python3

# DNP3pot - The Industrial Honeypot 
#
#Creative Commons 2019  <wachowsky.artur@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""
DNP3 Lib based on DNP3Lib.py and ported to Python3 by referefref [https://github.com/nrodofile/ScapyDNP3_lib]
Original author: Nicholas Rodofile
Updated by: James Brine
"""

import signal
import sys
import time
import collections
import select
import socket
import os
import chardet
import threading
import multiprocessing
from scapy.all import *
import DNP3_Lib
import logging

def listen(Ip, DNP3port):
    p.start()
    while 1:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 3)
            s.bind((Ip, DNP3port))
            s.listen(5)
        except socket.error:
            exit(1)

        conn, addr = s.accept()
        logger.info('New connection from {}'.format(addr))
        print('Received connection from {}'.format(addr))

        try:
            threading.Thread(target=new, args=(conn, addr)).start()
        except:
            print('Terrible Error!')
            import traceback
            traceback.print_exc()
            print("cannot bind port :(")
            exit(1)

def scapy(Ip, DNP3port):
    sniff(filter="host " + Ip + " and tcp port " + str(DNP3port) + " and greater 50", prn=packet_callback, store=0)

# Packet Inspection
def new(conn, addr):
    msg = conn.recv(2048)

    try:
        conn.send(banner)
        time.sleep(1.02)
        conn.close()
    except TypeError:
        conn.close()

    if not len(str(msg)) == 0:
        encoding = chardet.detect(msg)['encoding']
        logger.info('Raw data received from {} rawdata: {} encoding: {}'.format(addr, msg, encoding))
        # TODO FullPacket
    else:
        conn.close()
        return

# DNP3 SCAPY FILTER
def packet_callback(pkt):
    if pkt.haslayer(IP) and pkt[IP].dport == DNP3port and pkt[IP].dst == Ip and pkt.haslayer(DNP3):
        if pkt[TCP].payload:
            p = str(pkt.summary())
        else:
            p = 'No payload'
            logger.info('DNP3 application layer detected - No Payload src {} dport {} dst {} sval {} chcval {}'.format(pkt[IP].src, pkt[IP].dport, pkt[IP].dst, pkt.START, pkt.LENGTH))
        if not p == 'No payload':
            logger.info('DNP3 application layer detected - Payload: {} src {} dport {} dst {} sval {} chcval {}'.format(p, pkt[IP].src, pkt[IP].dport, pkt[IP].dst, pkt.START, pkt.LENGTH))

        # Pseudo Transport Layer Check
        if pkt.haslayer(DNP3_Lib.DNP3Transport):
            logger.info('DNP3 transport layer detected src {} dport {} dst {} FIN BIT {} FIR BIT {}'.format(pkt[IP].src, pkt[IP].dport, pkt[IP].dst, pkt.FIN, pkt.FIR))

        # Function codes check
        if pkt.haslayer(DNP3_Lib.DNP3ApplicationRequest):
            if pkt.FUNC_CODE is not None:
                if 0 <= pkt.FUNC_CODE <= 33:
                    logger.critical('\n DNP3 Function code {} detected {} ----{}----> {}:\n'.format(pkt.FUNC_CODE, pkt[IP].src, pkt[IP].dport, pkt[IP].dst))
                    send(response)

                if 33 < pkt.FUNC_CODE < 129:
                    logger.critical('\n DNP3 OUT OF RANGE Function code {} detected {} ----{}----> {}:\n'.format(pkt.FUNC_CODE, pkt[IP].src, pkt[IP].dport, pkt[IP].dst))

                if 129 <= pkt.FUNC_CODE <= 131:
                    logger.critical('\n DNP3 Function code {} detected {} ----{}----> {}:\n'.format(pkt.FUNC_CODE, pkt[IP].src, pkt[IP].dport, pkt[IP].dst))
                    send(response)

                if not 0 <= pkt.FUNC_CODE <= 131:
                    logger.critical('\n DNP3 OUT OF RANGE Function code {} detected {} ----{}----> {}:\n'.format(pkt.FUNC_CODE, pkt[IP].src, pkt[IP].dport, pkt[IP].dst))

def get_eth0_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except socket.error:
        return None

if __name__ == "__main__":
    print('Initialized')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger = logging.getLogger(__name__)
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler('/var/log/dnp3pot.log')
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s\n')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    DNP3 = DNP3_Lib.DNP3
    DNP3port = 20000

	# Remove original ip command exec and replace with python sockets implementation instead for better portability
    Ip = get_eth0_ip()
    if Ip:
        print("Eth0 IP address:", Ip)
    else:
        print("Failed to retrieve eth0 IP address. Exiting.")
        sys.exit(1)
    
    bind_layers(TCP, DNP3, dport=DNP3port)
    bind_layers(TCP, DNP3, sport=DNP3port)

    response = IP() / TCP() / '\x05\x64\x0A\x00\x01\x00\x05\x00\x39\x71\xC0\xF4\x82\x00\x00\x6F\xBA'
    banner = '\x05\x64\x0A\x00\x01\x00\x05\x00\x39\x71\xC0\xF4\x82\x00\x00\x6F\xBA'

    p = multiprocessing.Process(target=scapy, args=(Ip, DNP3port))
    
    try:
        listen(Ip, DNP3port)
    except KeyboardInterrupt:
        print('\nInterrupted')
        s.close()
        p.join()
        sys.exit(0)
