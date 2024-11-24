#
# Здесь реализован импорт необходимых для запуска приложения библиотек,
# функций запуск основного интерфейса прилоедния
#


from flask import Flask, render_template
import nmap


app = Flask(__name__)

@app.route('/')
def index():
        return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)