#
# Данный файл позваоляет взаимодействовать с базой sqllite
# 

import json
import sqlite3
import requests
import gzip
from io import BytesIO

# Скачивание базы данных с уязвимостями
def download_and_extract_json(url):
    response = requests.get(url)
    if response.status_code == 200:
        with gzip.GzipFile(fileobj=BytesIO(response.content)) as f:
            return json.load(f)
    else:
        print(f"Ошибка загрузки данных: {response.status_code}")
        return None


# Функция для получения описания уязвимости из sqllite
def get_description(cve_id):
    conn = sqlite3.connect('cve_database1.db')
    cursor = conn.cursor()
    query = "SELECT description FROM vulnerabilities WHERE cve_id = '" + cve_id + "'"
    
    cursor.execute(query)
    row = cursor.fetchall() 
    conn.close()
    if row:
        return row[0][0]
    return

# Основная функция 
def main_func():
    nvd_url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz'

    cve_data = download_and_extract_json(nvd_url)

    conn = sqlite3.connect('cve_database1.db')
    cursor = conn.cursor()

    # Создание таблицы в sqllite
    cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY,
        cve_id TEXT UNIQUE NOT NULL,
        description TEXT,
        published_date DATE
    )''')
    # Занесение в таблицу данных полученных с сайта
    for item in cve_data['CVE_Items']:
        cve_id = item['cve']['CVE_data_meta']['ID']
        description_data = item['cve']['description']['description_data']
        description = description_data[0]['value'] if description_data else 'Нет описания'
        published_date = item.get('publishedDate', None)

        cursor.execute('''INSERT OR IGNORE INTO vulnerabilities (cve_id, description, published_date)
                        VALUES (?, ?, ?)''', (cve_id, description, published_date))

    conn.commit()
    conn.close()

if __name__ == '__main__':
    main_func()