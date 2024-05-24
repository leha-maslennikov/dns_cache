import struct
from time import time
from dns_errors import *

A = 1
NS = 2
CNAME = 5
SOA = 6
PTR = 12
MX = 15
TXT = 16

dns_types = {
    A:'A',
    NS:'NS',
    CNAME:'CNAME',
    SOA:'SOA',
    PTR:'PTR',
    MX:'MX',
    TXT:'TXT'
}

class DNSRecord:
    name: bytes
    qtype: int
    ttl: int
    data: bytes

    def __init__(self, name: bytes, qtype: int, ttl: int, data: bytes) -> None:
        self.name = name
        self.qtype = qtype
        #время, когда запись будет не актуальной
        self.ttl = ttl + time()
        self.data = data

    def __bool__(self) -> bool:
        '''проверка на актуальность записи'''
        return (time() < self.ttl - 1)

    def get_bytes(self) -> bytes:
        '''байтовое представление записи'''
        record = self.name + struct.pack('!HHIH', self.qtype, 1, int(self.ttl - time()), len(self.data)) + self.data
        return record

class DNSPacket:
    packet: bytes
    id: int
    qr: int
    opcode: int
    aa: int
    tc: int
    rd: int
    z: int
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int
    requests: list[tuple[bytes, int]]
    records: list[DNSRecord]

    def __init__(self, packet: bytes = None) -> None:
        self.packet = packet
        self.id = 0
        self.opcode = 0
        self.aa = 0
        self.tc = 0
        self.rd = 0
        self.z = 0
        self.rcode = 0
        self.qdcount = 0
        self.ancount = 0
        self.nscount = 0
        self.arcount = 0
        self.requests = []
        self.records = []
        
    def ask(name: bytes, qtype: int) -> bytes:
        '''формирование пакета с запросом о name с типом qtype'''
        packet = DNSPacket()
        packet.id = int(time()) % 255
        packet.qr = 0
        packet.rcode = 0
        packet.requests = [(name, qtype)]
        return packet.get_bytes()

    def get_name(self, pos: int) -> tuple[bytes, int]:
        '''вспомагательная функция для извлечения днс имени из пакета'''
        end = pos
        while self.packet[end]:
            if self.packet[end] >> 6 == 0:
                end += self.packet[end] + 1
            else:
                return self.packet[pos:end] + self.get_name(struct.unpack('!H', self.packet[end:end+2])[0] % (2<<13))[0], end + 2
        return self.packet[pos:end+1], end+1

    def parse(self) -> None:
        '''парсинг пакета, который был передан в конструктор'''
        try:
            self.__parse__()
        except DNSError as err:
            raise err
        except Exception as err:
            raise DNSError('Undefined', err)
    
    def __parse__(self) -> None:
        '''парсинг пакета, который был передан в конструктор'''
        if (len(self.packet) < 12) or (len(self.packet) > 512):
            raise DNSError(len(self.packet), f'len(self.packet) = {len(self.packet)}')
        
        header = struct.unpack('!HBBHHHH', self.packet[:12])
        self.id = header[0]
        self.qr = header[1] >> 7
        self.opcode = (header[1] >> 3) % 16
        self.aa = (header[1] >> 2) % 2
        self.tc = (header[1] >> 1) % 2
        self.rd = header[1] % 2
        self.z = (header[2] >> 4) % 8
        self.rcode = header[2] % (2<<4)
        self.qdcount = header[3]
        self.ancount = header[4]
        self.nscount = header[5]
        self.arcount = header[6]
        
        #print(f'self.qdcount = {self.qdcount}, self.ancount = {self.ancount}, self.nscount = {self.nscount}, self.arcount = {self.arcount}')
        
        #проверка на корректность пакета и можем ли мы его обработать
        if not self.qr:
            if self.opcode > 2:
                raise FormatError(self.opcode, f'opcode = {self.opcode}')
            elif self.opcode > 0:
                #не реализована работа с opcode 1 и 2
                raise NotImplementedError(self.opcode, f'opcode = {self.opcode}')
            if self.tc:
                raise FormatError(self.tc, f'tc = {self.tc}')
        else:
            if self.tc:
                #не реализована работа по tcp
                raise InnerError(self.tc, f'tc = {self.tc}')
            if self.rcode != 0:
                raise RcodeError(self.rcode, f'rcode = {self.rcode}')
            
        body = 12
        self.requests = []
        for _ in range(self.qdcount):
            name, body = self.get_name(body)
            qtype, qclass = struct.unpack('!HH', self.packet[body:body+4])
            body += 4
            self.requests.append((name, qtype))
            #print(name.decode(), qtype, qclass)
        self.records = []
        for _ in range(self.ancount+self.nscount+self.arcount):
            name, body = self.get_name(body)
            qtype, qclass, ttl, rdlength = struct.unpack('!HHIH', self.packet[body:body+10])
            body += 10
            #print(name.decode(), qtype, qclass, ttl, rdlength)
            if qtype == NS:
                self.records.append(DNSRecord(name, qtype, ttl, self.get_name(body)[0]))
            elif qtype == MX:
                self.records.append(DNSRecord(name, qtype, ttl, self.packet[body:body+2] + self.get_name(body+2)[0]))
            else:
                self.records.append(DNSRecord(name, qtype, ttl, self.packet[body:body+rdlength]))
            body += rdlength

    def get_bytes(self) -> bytes:
        '''байтовое представление пакета'''
        flags = (b'\x80' if self.qr else b'\x00') + struct.pack('!B', self.rcode)
        header = struct.pack('!H', self.id) + flags + struct.pack('!HHHH', len(self.requests), len(self.records), 0, 0)
        body = b''
        for name, qtype in self.requests:
            body += name + struct.pack('!HH', qtype, 1)
        for record in self.records:
            body += record.get_bytes()
        return header + body
