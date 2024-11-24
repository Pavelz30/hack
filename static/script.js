let formCount = 1;

// Функция для переключения типа ввода
function toggleInput(selectElement) {
    const ipType = selectElement.value;
    const inputContainer = selectElement.parentElement.nextElementSibling;
    const singleIpInput = inputContainer.querySelector('.single');
    const cidrIpInput = inputContainer.querySelector('.cidr');
    const rangeIpInput = inputContainer.querySelector('.range');

    // Сохраняем текущее значение поля ввода
    const currentValue = singleIpInput.value || cidrIpInput.value || rangeIpInput.value;

    // Скрываем все поля ввода
    singleIpInput.style.display = 'none';
    cidrIpInput.style.display = 'none';
    rangeIpInput.style.display = 'none';

    // Отображаем соответствующее поле ввода и восстанавливаем значение
    if (ipType === 'single') {
        singleIpInput.style.display = 'block';
        singleIpInput.value = currentValue;
    } else if (ipType === 'cidr') {
        cidrIpInput.style.display = 'block';
        cidrIpInput.value = currentValue;
    } else if (ipType === 'range') {
        rangeIpInput.style.display = 'block';
        rangeIpInput.value = currentValue;
    }
}

// Функция для добавления новой формы
function addForm() {
    if (formCount >= 3) {
        document.getElementById('banner').style.display = 'block';
        return;
    }

    const formContainer = document.getElementById('form-container');
    const newFormGroup = document.createElement('div');
    newFormGroup.className = 'ip-form-group';
    newFormGroup.innerHTML = `
        <div class="select-input-container">
            <select class="ip-type" onchange="toggleInput(this)">
                <option value="single">IP в формате X.X.X.X</option>
                <option value="cidr">IP в CIDR нотации</option>
                <option value="range">IP в формате диапазона</option>
            </select>
        </div>
        <div class="input-container">
            <input type="text" class="ip-input single" placeholder="Введите IP в формате X.X.X.X" oninput="validateIP(this)">
            <input type="text" class="ip-input cidr" placeholder="Введите IP в CIDR нотации" style="display: none;" oninput="validateCIDR(this)">
            <input type="text" class="ip-input range" placeholder="Введите IP в формате диапазона" style="display: none;" oninput="validateRange(this)">
        </div>
    `;
    formContainer.appendChild(newFormGroup);
    formCount++;
    newFormGroup.scrollIntoView({ behavior: 'smooth' });
    document.querySelector('.remove-button').style.display = 'inline-block';
}

// Функция для удаления формы
function removeForm() {
    const formGroups = document.querySelectorAll('.ip-form-group');
    if (formGroups.length > 1) {
        formGroups[formGroups.length - 1].remove();
        formCount--;
        document.getElementById('banner').style.display = 'none';
    }
    if (formCount < 2) {
        document.querySelector('.remove-button').style.display = 'none';
    }
}

// Функция для отправки данных
function submitIP() {
    const formGroups = document.querySelectorAll('.ip-form-group');
    let allValid = true;
    formGroups.forEach(group => {
        const selectElement = group.querySelector('.ip-type');
        const ipType = selectElement.value;
        let ipInput;

        if (ipType === 'single') {
            ipInput = group.querySelector('.single').value;
            if (!validateIP(group.querySelector('.single'))) {
                allValid = false;
            }
        } else if (ipType === 'cidr') {
            ipInput = group.querySelector('.cidr').value;
            if (!validateCIDR(group.querySelector('.cidr'))) {
                allValid = false;
            }
        } else if (ipType === 'range') {
            ipInput = group.querySelector('.range').value;
            if (!validateRange(group.querySelector('.range'))) {
                allValid = false;
            }
        }
    });

    if (allValid) {
        formGroups.forEach(group => {
            const selectElement = group.querySelector('.ip-type');
            const ipType = selectElement.value;
            let ipInput;

            if (ipType === 'single') {
                ipInput = group.querySelector('.single').value;
                console.log('Введенные данные:', ipInput);
            } else if (ipType === 'cidr') {
                ipInput = group.querySelector('.cidr').value;
                console.log('Введенные данные:', ipInput);
            } else if (ipType === 'range') {
                ipInput = group.querySelector('.range').value;
                console.log('Введенные данные:', ipInput);
            }
        });
        document.getElementById('banner').style.display = 'none';
        document.getElementById('error-message').style.display = 'none';
    } else {
        document.getElementById('error-message').style.display = 'block';
    }
}

// Функция для валидации IP в формате X.X.X.X
function validateIP(input) {
    const value = input.value;
    const ipPattern = /^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(;((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))*$/;
    if (!ipPattern.test(value)) {
        input.style.borderColor = 'red';
        document.getElementById('error-message').style.display = 'block';
        return false;
    } else {
        input.style.borderColor = '';
        document.getElementById('error-message').style.display = 'none';
        return true;
    }
}

// Функция для валидации IP в CIDR нотации
function validateCIDR(input) {
    const value = input.value;
    const cidrPattern = /^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\/(3[0-2]|[1-2]?[0-9])(;((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\/(3[0-2]|[1-2]?[0-9]))*$/;
    if (!cidrPattern.test(value)) {
        input.style.borderColor = 'red';
        document.getElementById('error-message').style.display = 'block';
        return false;
    } else {
        input.style.borderColor = '';
        document.getElementById('error-message').style.display = 'none';
        return true;
    }
}

// Функция для валидации IP в формате диапазона
function validateRange(input) {
    const value = input.value;
    const rangePattern = /^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(-(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))?\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(-(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))?(;((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(-(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))?\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(-(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))?)*$/;

    if (!rangePattern.test(value)) {
        input.style.borderColor = 'red';
        document.getElementById('error-message').style.display = 'block';
        return false;
    } else {
        input.style.borderColor = '';
        document.getElementById('error-message').style.display = 'none';
    }

    // Проверка, что левое число всегда меньше или равно правое число
    const ranges = value.split(';');
    for (let range of ranges) {
        const parts = range.split('.');
        for (let part of parts) {
            const [left, right] = part.split('-');
            if (left && right && parseInt(left) > parseInt(right)) {
                input.style.borderColor = 'red';
                document.getElementById('error-message').style.display = 'block';
                return false;
            }
        }
    }
    input.style.borderColor = '';
    document.getElementById('error-message').style.display = 'none';
    return true;
}
