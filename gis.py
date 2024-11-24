#
# Данный файл предназначен для реализации обращения с утилитой nmap
#


import nmap
import ipaddress
import concurrent.futures


# Преобразование диапазона ip-адресов в список
def expand_ip_range(ip_range):
    ip_range = ip_range.split(';')
    ip_list = []
    for ip in ip_range:
        parts = ip.split('-')
        base_ip = parts[0]
        base_parts = base_ip.split('.')

        start = int(base_parts[-1])
        end = int(parts[1]) if len(parts) > 1 else start

        for i in range(start, end + 1):
            ip_parts = base_parts[:-1] + [str(i)]
            ip_list.append('.'.join(ip_parts))
    
    return ip_list


# Преобразование CIDR пормата ip-адресов в список
def parse_cidr_to_ips(cidr):
    ip_range = cidr.split(';')
    ip_list = []
    for ip in ip_range:
        network = ipaddress.ip_network(ip)
        ip_list += [str(ip) for ip in network.hosts()]
    return ip_list


# Предварительное обычное сканированеи ip-адресов, 
# возвращет список достпных для глубокого сканироания портов
def scan_open_ports(target):
    nm = nmap.PortScanner()
    # nm.scan(target, arguments='-sT -sU -p 1-65000 -T5 -', sudo=True)
    nm.scan(target, arguments='-p 1-1000 -T5', sudo=True)
    open_ports = []
    for proto in nm[target].all_protocols():
        lport = nm[target][proto].keys()
        open_ports.extend(port for port in lport)
    return open_ports

# Реализация глубокого сканирования, 
# ключающее в себя выполнение скрипта по поиску уязвимостей
# Возвращает объект типа nmap.PortScanner для взаимодействия с ним в будущем
def deep_service_scan(target, open_ports):
    nm = nmap.PortScanner()
    ports_str = ','.join(map(str, open_ports))
    nm.scan(target, ports_str, arguments='-sV --script vulners', sudo=True)
    return nm

# Функция, позволяющая осуществить распараллеливание сканирпования портов
# Здесь осуществляется вызов предварительного сканирования и глубокого
def process_ip(ip):
    open_ports = scan_open_ports(ip)
    if open_ports:
        return deep_service_scan(ip, open_ports)
    else:
        print(f"No open ports found for {ip}, deep scan not required.")
        return None


# Основная фнукция сканирования, из которой вызываются остальные
# Возвращает список объектов типа nmap.PortScanner для взаимодействия с ними в будущем
def main_scans(target_ip):
    if '-' in target_ip:
        expanded_ips = expand_ip_range(target_ip)
    elif '/' in target_ip:
        expanded_ips = parse_cidr_to_ips(target_ip)
    else:
        expanded_ips = target_ip.split(';')
    
    # Контекстный менеджер для распараллелиания сканирования
    with concurrent.futures.ProcessPoolExecutor() as executor:
        results_list = executor.map(process_ip, expanded_ips)
    return results_list
    