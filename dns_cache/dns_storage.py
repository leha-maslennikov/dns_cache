from dns_packet import DNSRecord

class DnsDataStorage:
    data: dict[bytes, list]

    def __init__(self) -> None:
        self.data = dict()

    def set(self, record: DNSRecord) -> None:
        '''добавление днс записи'''
        if record.name not in self.data:
            self.data[record.name] = []
        self.data[record.name].append(record)

    def get(self, name: bytes, qtype: int) -> list[DNSRecord]:
        '''запрос всех днс записей относящихся к name с типом qtype'''
        records = []
        if name not in self.data:
            return records
        for record in self.data[name]:
            record: DNSRecord = record
            if record.qtype == qtype:
                #проверка является ли запись актуальной, если - нет, то удалятся
                if record:
                    records.append(record)
                else:
                    self.data[name].remove(record)
        return records