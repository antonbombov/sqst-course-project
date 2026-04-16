"""
vulnerable-app/app.py — Учебное веб-приложение с намеренными уязвимостями
==========================================================================
Курс OTUS DevSecOps: SonarQube от А до Я
Урок 2: Быстрый старт — установка и первое сканирование

ВНИМАНИЕ: Этот код содержит НАМЕРЕННЫЕ уязвимости для учебных целей.
НЕ используйте этот код в production-окружении!

Уязвимости, детектируемые SonarQube Community Edition:
  ├── VULNERABILITY:
  │   ├── Hard-coded credentials (S2068/S6418, CWE-798) — пароли/токены в коде
  │   └── Binding 0.0.0.0 (S8392) — доступ со всех интерфейсов
  ├── SECURITY HOTSPOT:
  │   ├── CSRF disabled (S4502) — Flask без CSRF-защиты
  │   ├── Weak hashing (S4790) — MD5 хеширование
  │   └── Debug mode (S4507) — debug=True в production
  └── НЕ детектируемые CE (нужен Enterprise для taint analysis):
      ├── SQL Injection (CWE-89)
      ├── Command Injection (CWE-78)
      └── Path Traversal (CWE-22)
"""

import os
import sqlite3
import subprocess
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

# =============================================================================
# УЯЗВИМОСТЬ 1: Hard-coded credentials (CWE-798)
# SonarQube CE: S2068 — "Credentials should not be hard-coded"
# CE ловит переменные с "password"/"passwd"/"secret" в имени,
# а также пароли внутри connection string и известные форматы ключей
# =============================================================================
DB_PASSWORD = "admin123"          # S2068: пароль в коде
SECRET_KEY  = "mysecretkey12345"  # УЯЗВИМОСТЬ: секрет (CE может не поймать)
API_TOKEN   = "tok_prod_abc123xyz" # УЯЗВИМОСТЬ: токен (CE может не поймать)
DATABASE_URL = "postgresql://admin:P@ssw0rd@db:5432/prod"  # S6418: креды в connection string


def get_db_connection():
    """Создаёт подключение к базе данных."""
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Инициализирует базу данных с тестовыми данными."""
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)
    conn.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','admin123','admin')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','pass456','user')")
    conn.commit()
    conn.close()


# =============================================================================
# УЯЗВИМОСТЬ 2: SQL Injection (CWE-89)
# CE: НЕ детектируется (нужен taint analysis → Enterprise Edition)
# CE увидит только S2077 (SQL formatting) как Security Hotspot
# =============================================================================
@app.route("/login", methods=["POST"])
def login():
    """
    Небезопасная аутентификация — уязвима к SQL Injection.

    Пример атаки: username = "admin' --"
    Запрос становится: SELECT * FROM users WHERE username='admin' --' AND password='...'
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_db_connection()
    # УЯЗВИМОСТЬ: строковая конкатенация в SQL-запросе
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    user = conn.execute(query).fetchone()  # SQL INJECTION!
    conn.close()

    if user:
        return jsonify({"status": "ok", "role": user["role"]})
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# =============================================================================
# УЯЗВИМОСТЬ 3: Command Injection (CWE-78)
# CE: НЕ детектируется (нужен taint analysis → Enterprise Edition)
# CE увидит S4721 (OS command execution) как Code Smell
# =============================================================================
@app.route("/ping", methods=["GET"])
def ping():
    """
    Небезопасный пинг — уязвим к Command Injection.

    Пример атаки: host = "8.8.8.8; cat /etc/passwd"
    """
    host = request.args.get("host", "localhost")
    # УЯЗВИМОСТЬ: пользовательский ввод передаётся напрямую в shell
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)  # CMD INJECTION!
    return result.decode()


# =============================================================================
# УЯЗВИМОСТЬ 4: Path Traversal (CWE-22)
# CE: НЕ детектируется (нужен taint analysis → Enterprise Edition)
# =============================================================================
@app.route("/file", methods=["GET"])
def read_file():
    """
    Небезопасное чтение файлов — уязвимо к Path Traversal.

    Пример атаки: filename = "../../etc/passwd"
    """
    filename = request.args.get("filename", "readme.txt")
    base_dir = "/var/app/files"
    # УЯЗВИМОСТЬ: нет валидации пути
    filepath = os.path.join(base_dir, filename)  # PATH TRAVERSAL!
    with open(filepath) as f:
        return f.read()


# =============================================================================
# УЯЗВИМОСТЬ 5: Weak Cryptography (CWE-326 / CWE-327)
# CE: S4790 — детектируется как Security Hotspot (не Vulnerability)
# =============================================================================
def hash_password(password: str) -> str:
    """
    Небезопасное хеширование — использует MD5 без соли.
    MD5 считается криптографически слабым с 1996 года.
    """
    # УЯЗВИМОСТЬ: MD5 слаб, нет соли
    return hashlib.md5(password.encode()).hexdigest()  # WEAK CRYPTO!


# =============================================================================
# ЧИСТЫЙ КОД ДЛЯ СРАВНЕНИЯ: Правильный способ хеширования
# =============================================================================
import secrets

def hash_password_secure(password: str) -> str:
    """
    БЕЗОПАСНЫЙ вариант: bcrypt или argon2 с солью.
    Показываем студентам — вот как надо!
    """
    import hashlib
    salt = secrets.token_hex(16)
    # Используем SHA-256 с солью (в реальном коде — bcrypt/argon2)
    return hashlib.sha256((salt + password).encode()).hexdigest() + ":" + salt


# =============================================================================
# УЯЗВИМОСТЬ 6: XSS (CWE-79)
# =============================================================================
@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return f"<h1>Hello {name}</h1>" # XSS

if __name__ == "__main__":
    init_db()
    # УЯЗВИМОСТЬ: debug=True в production раскрывает трассировки ошибок
    app.run(host="0.0.0.0", port=5000, debug=True)
