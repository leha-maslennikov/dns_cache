import socket
from concurrent.futures import ThreadPoolExecutor
from dns_errors import *
from dns_packet import DNSPacket, DNSRecord, dns_types
from dns_storage import DnsDataStorage

class DNSCacheServer:
    forwarder: tuple[str, int]
    cache: DnsDataStorage
    __stop__: bool

    def __init__(self, forwarder: tuple[str, int] = ('8.8.8.8', 53)) -> None:
        self.forwarder = forwarder
        self.cache = DnsDataStorage()

    def stop(self):
        self.__stop__ = True

    def start(self, host: str = '', port: int = 53, threads_cnt: int = 3) -> None:
        '''запуск сервера'''
        self.__stop__ = False
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock,
            ThreadPoolExecutor(max_workers=threads_cnt) as exe
        ):
            self.sock = sock
            sock.bind((host, port))
            print('серевер успешно запущен')
            while not self.__stop__:
                data, addr = sock.recvfrom(512)
                exe.submit(self.handler, data, addr)

    def handler(self, data: bytes, addr: tuple[str, int]) -> None:
        '''обработчик входящих запросов'''
        packet = DNSPacket(data)
        #если при парсинге пакета или дальнейшей обработке запроса 
        #возникли проблемы,то устанавливается соответствующий 
        #ошибке rcode, для дальнейшей отправки ответного пакета
        try:
            packet.parse()
            if packet.qr:
                raise FormatError('qr != 0')
            packet.records = []
            for name, qtype in packet.requests:
                _from, data = self.get_info(name, qtype)
                packet.records.extend(data)
                print(f'{addr[0]}, {dns_types[qtype] if qtype in dns_types else qtype}, {name.decode()}, {_from}')
        except FormatError as err:
            print('FormatError', addr, err)
            packet.rcode = 1 
        except RcodeError as err:
            print('RcodeError',addr, err)
            packet.rcode = err.args[0]
        except NotImplemented as err:
            print('NotImplemented', addr, err)
            packet.rcode = 4
        except InnerError as err:
            print('InnerError', addr, err)
            packet.rcode = 2
        except DNSError as err:
            #ошибку обработать не получилось, поэтому запрос игнорируется
            print('pass', addr, err)
            return
        except Exception as err:
            print(addr, type(err), err)
            packet.rcode = 2
        packet.qr = 1
        #отправляется ответ
        self.sock.sendto(packet.get_bytes(), addr)
    
    def get_info(self, name: bytes, qtype: int) -> tuple[str, list[DNSRecord]]:
        '''запрос записей типа qtype о name'''
        #запрос данных из кэша
        records = self.cache.get(name, qtype)
        if records:
            return 'cache', records
        #запрос данных у основного сервера
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(DNSPacket.ask(name, qtype), self.forwarder)
            sock.settimeout(2)
            try:
                packet = DNSPacket(sock.recv(512))
            except TimeoutError:
                raise InnerError('primary server time out error')
            packet.parse()
            records = packet.records
            #кэшируем новые данные
            for record in packet.records:
                self.cache.set(record)
        return 'forwarder', records


if __name__ == '__main__':
    DNSCacheServer(forwarder=('192.168.31.1', 53)).start(host='192.168.31.172', port=100)