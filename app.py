from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3, time, os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "heurosamp"  # Troque depois por algo mais seguro

# ========================
# CONFIGS DE SEGURANÇA
# ========================
MAX_TENTATIVAS = 2        # limite de tentativas
BLOQUEIO_TEMPO = 60       # em segundos (1 minuto de bloqueio)
tentativas = {}           # salva tentativas por IP


# ========================
# BANCO DE DADOS
# ========================
def init_db():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    # Usuário admin
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                )''')

    # Projetos
    c.execute('''CREATE TABLE IF NOT EXISTS projetos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    titulo TEXT NOT NULL,
                    descricao TEXT,
                    link TEXT,
                    imagem TEXT
                )''')

    conn.commit()
    conn.close()


# ========================
# ROTAS PÚBLICAS
# ========================
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/projetos")
def projetos():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT * FROM projetos")
    projetos = c.fetchall()
    conn.close()
    return render_template("projetos.html", projetos=projetos)


# ========================
# LOGIN / PROTEÇÃO
# ========================
@app.route("/rais", methods=["GET", "POST"])   # login escondido em /rais
def login():
    ip = request.remote_addr
    agora = time.time()

    # Se o IP já falhou antes
    if ip in tentativas:
        falhas, ultimo_tempo = tentativas[ip]

        # Se passou do limite de tentativas
        if falhas >= MAX_TENTATIVAS and (agora - ultimo_tempo) < BLOQUEIO_TEMPO:
            tempo_restante = int(BLOQUEIO_TEMPO - (agora - ultimo_tempo))
            return f"🚫 Muitas tentativas falhadas. Tente novamente em {tempo_restante} segundos."

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session["user_id"] = user[0]
            tentativas[ip] = (0, agora)  # reset falhas
            return redirect(url_for("painel"))
        else:
            # Incrementa falhas
            if ip not in tentativas:
                tentativas[ip] = (1, agora)
            else:
                falhas, _ = tentativas[ip]
                tentativas[ip] = (falhas + 1, agora)

            flash("❌ Credenciais inválidas!")
            return redirect(url_for("login"))

    return render_template("login.html")


# ========================
# ROTAS PROTEGIDAS
# ========================
@app.route("/painel", methods=["GET", "POST"])
def painel():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    if request.method == "POST":
        titulo = request.form["titulo"]
        descricao = request.form["descricao"]
        link = request.form["link"]

        c.execute("INSERT INTO projetos (titulo, descricao, link) VALUES (?, ?, ?)",
                  (titulo, descricao, link))
        conn.commit()
        conn.close()
        return redirect(url_for("projetos"))

    c.execute("SELECT * FROM projetos")
    projetos = c.fetchall()
    conn.close()

    return render_template("painel.html", projetos=projetos)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ========================
# MAIN
# ========================
if __name__ == "__main__":
    init_db()

    # Criar usuário fixo "heuro55" se não existir
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", ("heuro55",))
    if not c.fetchone():
        senha_hash = generate_password_hash("933588855&a")
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ("heuro55", senha_hash))
        conn.commit()
    conn.close()

    # Render exige que rode na porta fornecida
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

