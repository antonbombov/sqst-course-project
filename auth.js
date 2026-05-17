const crypto = require('crypto');

// =============================================================================
// УЯЗВИМОСТЬ 1: Hard-coded secrets (S2068)
// =============================================================================
const SECRET_KEY = "hardcoded_secret_12345";
const PASSWORD = "super_secret_admin_password";

// =============================================================================
// УЯЗВИМОСТЬ 2: Weak password hashing (CWE-327) — S4790
// =============================================================================
function hashPassword(password) {
    // MD5 — слабый хеш, без соли
    return crypto.createHash('md5').update(password).digest('hex');
}

// =============================================================================
// УЯЗВИМОСТЬ 3: Timing attack vulnerability (CWE-208) — S5542
// =============================================================================
function verifyPassword(plain, hash) {
    // S5542 — простая константная проверка, уязвима к timing attack
    return hashPassword(plain) === hash;
}

// =============================================================================
// УЯЗВИМОСТЬ 4: Global variable pollution (S3637)
// =============================================================================
global.userSession = {};  // Глобальная переменная — утечка данных

// =============================================================================
// АНТИПАТТЕРН 1: Always true condition (S2583)
// =============================================================================
function checkAdmin(user) {
    if (user && user.role === 'admin') {
        return true;
    } else if (user.role !== 'admin') {
        // Условие всегда истинно, если прошли в else
        return false;
    }
    return null;
}

// =============================================================================
// АНТИПАТТЕРН 2: Empty catch block (S2486)
// =============================================================================
function parseJSON(data) {
    try {
        return JSON.parse(data);
    } catch(e) {
        // Пустой catch — ошибка игнорируется
    }
    return null;
}

// =============================================================================
// АНТИПАТТЕРН 3: Deeply nested callback (S1066) + duplicated code (S4144)
// =============================================================================
function getUserRole(userId, callback) {
    // Глубоко вложенный колбэк — callback hell
    getDBConnection((conn) => {
        conn.query(`SELECT role FROM users WHERE id = ${userId}`, (err, rows) => {  // SQL injection!
            if (err) {
                callback(null);
            } else {
                if (rows && rows.length > 0) {
                    callback(rows[0].role);
                } else {
                    callback(null);
                }
            }
        });
    });
}

// Дублирование кода — S4144
function fetchUserRole(userId, callback) {
    getDBConnection((conn) => {
        conn.query(`SELECT role FROM users WHERE id = ${userId}`, (err, rows) => {
            if (err) {
                callback(null);
            } else {
                if (rows && rows.length > 0) {
                    callback(rows[0].role);
                } else {
                    callback(null);
                }
            }
        });
    });
}

// =============================================================================
// АНТИПАТТЕРН 4: Double negation (S2760)
// =============================================================================
function isNotInvalid(user) {
    return !!(user && user.active);  // странная двойная инверсия
}

// =============================================================================
// УЯЗВИМОСТЬ 5: Insecure default export — утечка API
// =============================================================================
function authenticate(username, password) {
    // Сравнение с хардкодом
    if (username === 'admin' && password === 'admin123') {
        return { success: true, token: `token_${Math.random()}` };
    }
    return { success: false };
}

// =============================================================================
// УЯЗВИМОСТЬ 6: Information exposure через error объекты
// =============================================================================
function validateEmail(email) {
    try {
        const re = /^[^\s@]+@([^\s@]+\.)+[^\s@]+$/;
        return re.test(email);
    } catch(e) {
        // Возвращаем детали ошибки
        return { error: e.message, stack: e.stack };
    }
}

// =============================================================================
// ХАРАКТЕРИСТИКИ, КОТОРЫЕ ДОЛЖНЫ БЫТЬ ОБНАРУЖЕНЫ SONARQUBE:
// 1. S2068 — hardcoded SECRET_KEY, PASSWORD
// 2. S4790 — MD5 хеширование
// 3. S5542 — timing attack в verifyPassword
// 4. S3637 — global.userSession
// 5. S2583 — всегда истинное/ложное условие
// 6. S2486 — пустой catch
// 7. S1066 — глубоко вложенный callback
// 8. S4144 — дублирование кода (getUserRole / fetchUserRole)
// 9. S2760 — двойное отрицание
// 10. S3827 — неиспользуемая переменная (добавлена специально)
// 11. S4507 — утечка информации через ошибки
// 12. S3649 — SQL injection в getUserRole
// 13. S1523 — eval в app.js
// 14. S5247 — XSS в app.js
// 15. S4721 — command injection в app.js
// 16. S5131 — path traversal в app.js
// 17. S2245 — Math.random в generateResetToken
// 18. S4568 — небезопасные cookie
// 19. S5443 — HTTP вместо HTTPS
// 20. S5691 — extended: true в body-parser
// =============================================================================

module.exports = {
    hashPassword,
    verifyPassword,
    authenticate,
    getUserRole,
    parseJSON,
    generateResetToken
};
