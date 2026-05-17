const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const auth = require('./auth');  // пользовательская "защита"
const session = require('express-session');

const app = express();

// =============================================================================
// УЯЗВИМОСТЬ 1: Hard-coded credentials (CWE-798) — S2068
// =============================================================================
const DB_PASSWORD = "root123";        // пароль в коде
const JWT_SECRET = "jwtsecret12345";  // секрет в коде
const API_KEY = "sk_live_4eR56T7yU8i";

// =============================================================================
// УЯЗВИМОСТЬ 2: Debug mode + verbose errors (S4507)
// =============================================================================
process.env.NODE_ENV = 'development';

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));  // S5691 — extended mode может приводить к prototype pollution

// =============================================================================
// УЯЗВИМОСТЬ 3: Небезопасная конфигурация сессии
// =============================================================================
app.use(session({
    secret: JWT_SECRET,
    resave: false,
    saveUninitialized: true,  // S3330 — генерирует сессии для неаутентифицированных
    cookie: {
        secure: false,         // S4568 — allow HTTP cookies
        httpOnly: false,       // S4568 — XSS может украсть куки
        maxAge: 365 * 24 * 3600000  // Год — очень долго
    }
}));

// =============================================================================
// УЯЗВИМОСТЬ 4: SQL Injection (CWE-89) — S3649
// =============================================================================
const db = new sqlite3.Database('./app.db');

// Инициализация БД с тестовыми данными
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)");
    db.run("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin')");
    db.run("INSERT OR IGNORE INTO users VALUES (2, 'user', 'pass456', 'user')");
});

// УЯЗВИМОСТЬ: строковая конкатенация SQL
app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    // S3649 — SQL injection через конкатенацию
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    db.get(query, (err, row) => {
        if (err) {
            console.log("Database error: " + err);  // S4507 — утечка деталей ошибки
            res.status(500).send("Error");
            return;
        }
        if (row) {
            req.session.user = row;
            res.json({ status: "ok", role: row.role });
        } else {
            res.status(401).json({ status: "error" });
        }
    });
});

// =============================================================================
// УЯЗВИМОСТЬ 5: Command Injection (CWE-78) — S4721
// =============================================================================
const { exec } = require('child_process');

app.get('/ping', (req, res) => {
    const host = req.query.host || 'localhost';
    // S4721 — command injection через shell
    exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
        if (error) {
            res.send(`Error: ${error.message}`);
            return;
        }
        res.send(stdout);
    });
});

// =============================================================================
// УЯЗВИМОСТЬ 6: Path Traversal (CWE-22) — S5131
// =============================================================================
const fs = require('fs');
const path = require('path');

app.get('/read', (req, res) => {
    const filename = req.query.file;
    // УЯЗВИМОСТЬ: path traversal через '../'
    const filepath = path.join('/var/app/data/', filename);
    fs.readFile(filepath, 'utf8', (err, data) => {
        if (err) {
            res.status(404).send('File not found');
            return;
        }
        res.send(data);
    });
});

// =============================================================================
// УЯЗВИМОСТЬ 7: XSS (CWE-79) — S5247
// =============================================================================
app.get('/hello', (req, res) => {
    const name = req.query.name || 'Guest';
    // S5247 — XSS через неэкранированный вывод
    res.send(`<h1>Hello ${name}</h1>`);
});

// =============================================================================
// УЯЗВИМОСТЬ 8: eval() usage (CWE-95) — S1523
// =============================================================================
app.post('/calculate', (req, res) => {
    const expression = req.body.expr;
    // S1523 — eval на пользовательском вводе = RCE
    const result = eval(expression);
    res.json({ result });
});

// =============================================================================
// УЯЗВИМОСТЬ 9: Insecure random token — S2245
// =============================================================================
function generateResetToken() {
    // Math.random не криптографически стойкий
    return Math.random().toString(36).substring(2, 15);
}

// =============================================================================
// АНТИПАТТЕРНЫ / ОШИБКИ КОДА
// =============================================================================

// S3827 — unused variable (мусорная переменная)
const UNUSED_CONSTANT = "this is never used";

// S111 — console.log в продакшене
console.log("Server starting on port 3000");

// S3984 — необработанное исключение в промисах
Promise.reject(new Error("Unhandled rejection!"));

// S4823 — использование async без await внутри (неправильная сигнатура)
async function syncFunction() {
    return "I am async but do nothing async";
}

// S5332 — использование HTTP вместо HTTPS
const server = app.listen(3000, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:3000`);
});

// S4507 — утечка стека в ответе
app.get('/crash', (req, res) => {
    throw new Error('Intentional crash');  // вернёт стек в ответ
});

// S2993 — небезопасный экспресс-роут, порядок важен, но можно переопределить
app.use((err, req, res, next) => {
    res.status(500).send('Something broke!');
});

module.exports = app;
