from multiprocessing import Pool
from argparse import ArgumentParser
from Scanner import PortScanner


if __name__ == '__main__':
    try:
        parser = ArgumentParser(description='Сканер')
        parser.add_argument('host', type=str, help='Хост для сканирования')
        parser.add_argument('-l', '--start', default=1, type=int, help='Нижняя граница')
        parser.add_argument('-r', '--end', default=200, type=int, help='Верхняя граница')
        parser.add_argument('-t', '--timeout', default=100, type=int, help='Timeout')
        parser.add_argument('-tcp', action='store_true', help='Сканировать открытые TCP порты')
        parser.add_argument('-udp', action='store_true', help='Сканировать открытые UDP порты')
        parser.add_argument('-p', '--processes', default=10, type=int, help='Количество потоков')

        args = parser.parse_args()
        if not args.tcp and not args.udp:
            args.tcp = args.udp = True
        scanner = PortScanner(args.host, args.timeout)
        pool = Pool(args.processes)
        if args.tcp:
            scan = pool.imap(scanner.tcp_scanner, range(args.start, args.end + 1))
            for port, protocol in scan:
                if protocol:
                    print(f'TCP порт {port} открыт. Протокол: {protocol}')
        if args.udp:
            scan = pool.imap(scanner.udp_scanner, range(args.start, args.end + 1))
            for port, protocol in scan:
                if protocol:
                    print(f'UDP порт {port} открыт. Протокол: {protocol}')
    except PermissionError:
        print('Необходимы права администратора')
    except KeyboardInterrupt:
        print('Interrupt')
