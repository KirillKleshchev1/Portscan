from re import match
from struct import unpack


DNS_TRANSACTION_ID = b'\x13\x37'


DNS_PACKET = DNS_TRANSACTION_ID + \
    b'\x01\x00\x00\x01' + \
    b'\x00\x00\x00\x00\x00\x00' + \
    b'\x02\x65\x31\x02\x72\x75' + \
    b'\x00\x00\x01\x00\x01'


NTP_PACKET = b'\x1b' + 47 * b'\0'


TCP_PACKETS = {
    'HTTP': b'\0',
    'SMTP': b'EHLO',
    'DNS': DNS_PACKET,
    'POP3': b'AUTH',
    'IMAP': b'LOGIN'
}


UDP_PACKETS = {
    'DNS': DNS_PACKET,
    'NTP': NTP_PACKET
}


CHECKER = {
    'HTTP': lambda packet: b'HTTP' in packet,
    'POP3': lambda packet: packet.startswith(b'+'),
    'DNS': lambda packet: packet.startswith(DNS_TRANSACTION_ID),
    'SMTP': lambda packet: match(b'[0-9]{3}', packet[:3]),
    'IMAP': lambda packet: check_imap(packet),
    'NTP': lambda packet: check_ntp(packet),
}


def check_imap(packet):
    if b'IMAP' in packet:
        return True
    else:
        return False


def check_ntp(packet):
    try:
        unpack('!BBBb11I', packet)
        return True
    except Exception:
        return False
