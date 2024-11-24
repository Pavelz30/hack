#
# Данный фалй предназначен для анализа базы данных MongoDB,
# создания pdf-файла и создания диаграмм
#



from fpdf import FPDF
from matplotlib import pyplot as plt
from pymongo import MongoClient
import pandas as pd

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Image, PageBreak, Paragraph,  Spacer
from reportlab.lib.styles import getSampleStyleSheet


from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import matplotlib.pyplot as plt
import io

# Создание столбчатой диаграммы о типах и количествах портов
def create_chart(data):
    states = {'open': 0, 'closed': 0, 'filtered': 0}

    for item in data:
        state = item.get('state', 'unknown')
        if state in states:
            states[state] += 1

    plt.figure(figsize=(6, 4))
    plt.bar(states.keys(), states.values(), color=['green', 'red', 'orange'])
    plt.title('Состояния портов')
    plt.xlabel('Состояние')
    plt.ylabel('Количество')

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    return buf

# Создание столбчатой диаграммы о количестве открытых портов
#  для кажого сканируемого ip
def create_ports_chart(data):
    ip_ports_count = {}

    for item in data:
        ip = item.get('ip', 'N/A')
        state = item.get('state', 'unknown')
        if state == 'open':
            if ip not in ip_ports_count:
                ip_ports_count[ip] = 0
            ip_ports_count[ip] += 1
    ip_ports_count = dict(sorted(ip_ports_count.items(), key=lambda item: item[1], reverse=True)[:10])

    plt.figure(figsize=(10, 6))
    bars = plt.bar(ip_ports_count.keys(), ip_ports_count.values(), color='green')
    plt.xticks(rotation=45, ha='right')
    plt.title('Количество открытых портов на IP адрес')
    plt.xlabel('IP адрес')
    plt.ylabel('Количество открытых портов')
    plt.tight_layout()

    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 0.05, int(yval), ha='center', va='bottom')

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close()
    return buf


# Создание круговой диаграммы распределния уязвимостей по критичности
def create_vulnerability_pie_chart(data):
    levels = {
        'Информационный': 0,
        'Средний': 0,
        'Высокий': 0,
        'Критичный': 0
    }

    for item in data:
        script = item.get('script', None)
        if script:
            for cvei in script:
                cvss = float(cvei[1])
                if cvss <= 2.5:
                    levels['Информационный'] += 1
                elif 3.0 < cvss <= 6.0:
                    levels['Средний'] += 1
                elif 6.0 < cvss <= 8.5:
                    levels['Высокий'] += 1
                else:
                    levels['Критичный'] += 1

    labels = list(levels.keys())
    sizes = list(levels.values())
    colors = ['lightblue', 'yellow', 'orange', 'red']
    
    plt.figure(figsize=(8, 8))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=colors)
    plt.title('Распределение уязвимостей по уровням критичности')
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close()
    return buf

# Функция для получения коллекции из MongoDB
def fetch_data_from_mongo(collection_name):
    client = MongoClient('localhost', 27017)
    db = client['scans']
    collection = db[collection_name]
    documents = collection.find()
    data = list(documents)
    client.close()
    return data


# Оснафная функция генерации дашборда 
def generate_pdf(data, chart_buffer, filename='scan_report.pdf'):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    elements = []
    # Задание пользовательского шрифта
    pdfmetrics.registerFont(TTFont('DejaVu', '/home/pavel/hack/dejavu-fonts-ttf-2.37/ttf/DejaVuSans.ttf'))
    
    # Кастомизация стилей
    styles = getSampleStyleSheet()
    custom_style = styles['Normal'].clone('CustomStyle') 
    custom_style.fontName = 'DejaVu' 
    custom_style.fontSize = 30
    custom_style.textColor = colors.HexColor('#333333')
    custom_style.alignment = 1

    # Заголовок документа
    centered_text = Paragraph("Отчет о сканировании периметра", custom_style)
    elements.append(Spacer(1, 200)) 
    elements.append(centered_text)
    elements.append(Spacer(1, 200)) 
    elements.append(PageBreak())

    lst_ips = set([ ip.get('ip', 'N/A') for ip in data])
    lst_ports = set([(ip.get('port', 'N/A'), ip.get('protocol', 'N/A')) for ip in data])
    lst_services = set([(ip.get('product', 'N/A'), ip.get('version', 'N/A')) for ip in data])
    couner = {ip.get('ip', "N/A"): 0 for ip in data}

    for ip in data:
        couner[ip.get('ip', "N/A")] += len(ip.get('script', '') if ip.get('script', '') else '')
    
    # Основной текст документа
    custom_style.fontSize = 16
    custom_style.leading = 20
    centered_text = Paragraph(f'Были просканированы следующие ip-адреса: {lst_ips}', custom_style)
    elements.append(centered_text)
    elements.append(Spacer(1, 30)) 
    centered_text = Paragraph(f'Были просканированы следующие порты: {lst_ports}', custom_style)
    elements.append(centered_text)  
    elements.append(Spacer(1, 30)) 
    centered_text = Paragraph(f'Сервисы, обнаруженные в сканируемом периметре: {lst_services}', custom_style)
    elements.append(centered_text)  
    elements.append(Spacer(1, 30))
    centered_text = Paragraph(f'Количество найденных уязвимостей для каждого ip: {couner}', custom_style)
    elements.append(centered_text)  
    elements.append(PageBreak())

    # Блок с диаграммами
    centered_text = Paragraph(f'Аналитическая информаиция', custom_style)
    elements.append(centered_text)
    elements.append(Spacer(1, 30))

    img = Image(chart_buffer, width=400, height=300)
    elements.append(img)
    elements.append(PageBreak())

    chart_buffer = create_ports_chart(data)
    img = Image(chart_buffer, width=450, height=300)
    elements.append(img)
    elements.append(PageBreak())
    
    chart_buffer = create_vulnerability_pie_chart(data)
    img = Image(chart_buffer, width=450, height=450)
    elements.append(img)
    elements.append(PageBreak())

    # Таблица с информацией о портах и сервисах
    fixed_col_widths = [100, 150, 100, 100, 100, 150] 

    columns = ['IP-адрес', 'Имя хоста', 'Сервис/Версия', 'Порт/Протокол', 'Протокол L7', 'Статус порта']
    table_data = [columns]

    for item in data:
        ip = item.get('ip', 'N/A')
        hostname = ', '.join(item.get('hostname', []))
        service_version = f"{item.get('product', 'N/A')}/{item.get('version', 'N/A')}"
        port_protocol = f"{item.get('port', 'N/A')}/{item.get('protocol', 'N/A')}"
        status = item.get('state', 'N/A')
        l7_protocol = item.get('name', 'N/A')

        row = [ip, hostname, service_version, port_protocol, l7_protocol, status]
        table_data.append(row)


    # Таблица с информацией об уязвимостях в сканируемом контуре
    columns2 = ['CVE', 'Имя хоста', 'Сервис/Версия', 'Порт/Протокол', 'CVSS V2', 'Описание']
    table_data_2 = [columns2]
    for item in data:
        hostname = Paragraph(', '.join(item.get('hostname', [])))
        service_version = Paragraph(f"{item.get('product', 'N/A')}/{item.get('version', 'N/A')}")
        port_protocol = f"{item.get('port', 'N/A')}/{item.get('protocol', 'N/A')}"
        status = item.get('state', 'N/A')
        l7_protocol = item.get('name', 'N/A')
        script  = item.get('script', [])
        if script:
            for cvei in script:
                cve = cvei[0]
                cvss = cvei[1]
                description = cvei[3]
                if description:
                    description = Paragraph(cvei[3][:300] + '...')
                row = [cve, hostname, service_version, port_protocol, cvss, description]
                table_data_2.append(row)


    table = Table(table_data)
    table2 = Table(table_data_2, colWidths=fixed_col_widths)

    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.white),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'DejaVu'),  # Используем зарегистрированный шрифт
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ])
    table.setStyle(style)
    table2.setStyle(style)
    
    centered_text = Paragraph(f'Информация о портах и сервисах', custom_style)
    elements.append(centered_text) 
    elements.append(Spacer(1, 30))

    elements.append(table)
    elements.append(PageBreak()) 

    doc.pagesize = landscape(letter)
    elements.append(PageBreak())
    centered_text = Paragraph(f'Информация об уязвимостях в сканируемом контуре', custom_style)
    elements.append(centered_text) 
    elements.append(Spacer(1, 30))
    elements.append(table2)

    doc.build(elements)

# Основная функция файла
def mainpdf(collection_name):
    data = fetch_data_from_mongo(collection_name)
    chart_buffer = create_chart(data)
    generate_pdf(data,chart_buffer,'scan_summary.pdf')
    