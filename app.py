#
# Основной файл приложения
# 

from multiprocessing import Pool, Semaphore
import nmap
import json
import vulners
from pymongo import MongoClient
from datetime import datetime
import gis
import genpdf
from expdb import get_description, main_func

max_concurrent_scans = 5 
semaphore = Semaphore(max_concurrent_scans)

# Валидирование данных из поля scrip (данные об уязвимостях)
#  полченых от nmap
def valid_script(data):
    data = data.get('vulners', None)
    if not data:
        return
    lines = data.strip().split('\n') 
    list_of_lists = []

    for line in lines[1:]:
        elements = line.strip().split('\t') 
        if elements and 'CVE-' in elements[0]:
            elements.append(get_description(str(elements[0])))
            list_of_lists.append(elements) 

    return list_of_lists

# Заполенение базы MongoDB
def insert_data(nm: nmap.PortScanner, collection):
    document_info = {}
    if not collection.find():
        for proto, data in nm.scaninfo().items():
            if data.get('services', None):
                document_info[proto] = data['services']
        document_info['timestr'] = nm.scanstats().get('timestr', None)
        collection.insert_one(document_info)
    
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port].get('script', None):
                    valid_script_result = valid_script(nm[host][proto][port]['script'])
                else:
                    valid_script_result = None
                document = {
                    'ip': host,
                    'hostname': [dic['name'] for dic in nm[host]['hostnames']],
                    'status': nm[host]['status']['state'],
                    'protocol': proto,
                    'port': port,
                    'state': nm[host][proto][port]['state'],
                    'name': nm[host][proto][port]['name'],
                    "product": nm[host][proto][port]['product'] if nm[host][proto][port]['product'] != '' else None,
                    "version": nm[host][proto][port]['version'] if nm[host][proto][port]['version'] != '' else None,
                    'script': valid_script_result
                }
                collection.insert_one(document)

# Основная функция бекенда
def main():
    main_func()
    client = MongoClient('localhost', 27017)
    db = client['scans']
    hosts = '45.67.229.226-228'
    lst_nm = gis.main_scans(hosts)

    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    collection_name = f'scans_{timestamp}'
    collection = db[collection_name]
    for nm in lst_nm:   
        insert_data(nm, collection)
    # Cоздание пдф-файла
    genpdf.mainpdf(collection_name)
    client.close()


if __name__ == '__main__':
    main()