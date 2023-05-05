import socket
from struct import pack
from CONST import TCP_PACKETS, UDP_PACKETS, CHECKER


class PortScanner:

    def __init__(self, dest, timeout):
        self.dest = dest
        self.timeout = timeout / 1000

    def tcp_scanner(self, port):
        socket.setdefaulttimeout(self.timeout)
        for protocol, packet in TCP_PACKETS.items():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                try:
                    sock.connect((self.dest, port))
                except socket.timeout:
                    return port, None
                try:
                    if protocol == 'DNS':
                        packet = pack('!H', len(packet)) + packet
                    sock.send(packet)
                    packet = sock.recv(128)
                    if protocol == 'DNS':
                        packet = packet[2:]
                    if CHECKER[protocol](packet):
                        return port, protocol
                except socket.error:
                    continue
        return port, 'Неизвестный протокол'

    def udp_scanner(self, port):
        socket.setdefaulttimeout(self.timeout)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for protocol, packet in UDP_PACKETS.items():
                sock.sendto(packet, (self.dest, port))
                try:
                    if CHECKER[protocol](sock.recv(128)):
                        return port, protocol
                except socket.error:
                    continue
        return port, None
