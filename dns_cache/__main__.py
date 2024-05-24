from dns_cache_server import DNSCacheServer
from threading import Thread

def main():
    from sys import argv
    HELP = '''-h, --help
    для вызова справки
--port N 
    N - порт, на котором будет работать сервер, по умоланию 53
-p N
    то же, что и --port N
--forwarder host[:port]
    указание forwarder сервера, к которому следует обращатся,
    если порт не указан, то по умолчанию 53. По умолчанию 
    8.8.8.8:53.
-f host[:port]
    то же, что и --forwarder host[:port]
exit 
    чтобы остановть работу сервера
    
Примеры:
dns_cache
dns_cache -p 100
dns_cache -f 1.1.1.1:77
dns_cache -f 1.1.1.1 -p 88'''
    port = 53
    forwarder = ('8.8.8.8', 53)
    i = 1
    try:
        while i < len(argv):
            if argv[i] in ['-h', '--help']:
                print(HELP)
                return
            elif argv[i] in ['-p', '--port']:
                port = int(argv[i+1])
                i+=2
            elif argv[i] in ['-f', '--forwarder']:
                i += 1
                if ':' in argv[i]:
                    h, p = argv[i].split(':')
                    forwarder = (h, int(p))
                else:
                    forwarder = (argv[i], 53)
                i += 1
            else:
                print(HELP)
                return
    except Exception:
        print(HELP)
        return
    
    server = DNSCacheServer(forwarder=forwarder)

    Thread(target=server.start, kwargs={'port':port}, daemon=True).start()
    
    while input() != 'exit':
        pass
    server.stop()
    

if __name__ == '__main__':
    main()