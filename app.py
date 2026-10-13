"""
IDOR Challenge — "InvoicePortal"
=================================
A deliberately vulnerable Flask app for teaching Insecure Direct Object
Reference (IDOR). Everything lives in one file, uses only sqlite3 (stdlib)
and Flask, and resets its data every time it starts.

THE BUG (on purpose): /invoice/<id> fetches an invoice by id and shows it
to WHOEVER is logged in, without ever checking that the invoice actually
belongs to them. A logged-in user only ever sees their OWN invoice ids
listed on their dashboard — but nothing stops them from guessing or
incrementing the id in the URL to view someone else's invoice. The flag
sits in an invoice belonging to "admin", an account students are never
given credentials for.

Run locally:
    pip install -r requirements.txt
    python3 app.py
Then open http://127.0.0.1:5000

Deploy: see render.yaml / Procfile in this folder.
"""

from flask import Flask, request, redirect, session, render_template_string
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "workshop-demo-not-for-production")
# Render's disk is ephemeral and the db resets on every boot anyway (see
# init_db below), so /tmp is fine — no persistent volume needed.
DB = os.environ.get("DB_PATH", "/tmp/invoiceportal.db")


# ---------------------------------------------------------------------------
# Database setup — runs fresh every time the app starts
# ---------------------------------------------------------------------------
def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT
    )""")
    c.execute("""CREATE TABLE invoices (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        item TEXT,
        amount TEXT
    )""")

    users = [
        (1, "alice", "hunter2"),
        (2, "bob",   "password123"),
        (3, "carol", "letmein"),
        (4, "admin", "S3cureAdminPass!"),   # no login hint is ever given for this account
    ]
    c.executemany("INSERT INTO users (id, username, password) VALUES (?, ?, ?)", users)

    invoices = [
        (1001, 1, "Web hosting — March",      "$12.00"),
        (1002, 1, "Domain renewal",           "$9.50"),
        (1003, 2, "Web hosting — March",      "$12.00"),
        (1004, 2, "Design consultation",      "$85.00"),
        (1005, 3, "Web hosting — March",      "$12.00"),
        (1006, 4, "Server infrastructure — Q1", "FLAG{1d0r_m3ans_1_trust_ur_1d}"),
    ]
    c.executemany("INSERT INTO invoices (id, user_id, item, amount) VALUES (?, ?, ?, ?)", invoices)

    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


# Initialize the database as soon as the module is imported, so this works
# both with `python3 app.py` (local dev server) and under a WSGI server like
# gunicorn, which imports this file as `app:app` and never runs the
# `if __name__ == "__main__"` block below. Run gunicorn with a single worker
# (see Procfile) so two workers don't race to reset the same sqlite file.
init_db()


# ---------------------------------------------------------------------------
# Templates (inline, kept intentionally plain)
# ---------------------------------------------------------------------------
LAYOUT = """
<!doctype html>
<html><head><title>InvoicePortal</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f1216;color:#e8e8e8;max-width:720px;margin:60px auto;padding:0 20px}
a{color:#4fd6c4}
.card{background:#171c22;border:1px solid #262d35;border-radius:12px;padding:28px;margin-top:20px}
input{display:block;width:100%;padding:10px;margin:8px 0 16px;background:#0f1216;border:1px solid #333;color:#eee;border-radius:6px;box-sizing:border-box}
button{background:#4fd6c4;color:#0c2420;border:none;padding:10px 20px;border-radius:6px;font-weight:600;cursor:pointer}
.err{color:#ff6b6b}
table{width:100%;border-collapse:collapse;margin-top:10px}
td,th{padding:10px;border-bottom:1px solid #262d35;text-align:left}
.flag{color:#4fd6c4;font-weight:700}
</style></head>
<body><h1>📄 InvoicePortal</h1>{{ body|safe }}</body></html>
"""

def page(body):
    return render_template_string(LAYOUT, body=body)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    if "user_id" in session:
        return redirect("/dashboard")
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        ).fetchone()
        conn.close()
        if row:
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            return redirect("/dashboard")
        error = '<p class="err">Invalid username or password.</p>'

    body = f"""
    <div class="card">
      <h2>Log in</h2>
      {error}
      <form method="post">
        <label>Username</label>
        <input name="username" autocomplete="off">
        <label>Password</label>
        <input name="password" type="password">
        <button type="submit">Log in</button>
      </form>
      <p style="color:#888;font-size:14px">Demo accounts: alice/hunter2, bob/password123, carol/letmein</p>
    </div>
    """
    return page(body)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")
    conn = get_db()
    invoices = conn.execute(
        "SELECT id, item FROM invoices WHERE user_id = ?",
        (session["user_id"],)
    ).fetchall()
    conn.close()

    rows = "".join(
        f'<tr><td>#{inv["id"]}</td><td>{inv["item"]}</td>'
        f'<td><a href="/invoice/{inv["id"]}">View</a></td></tr>'
        for inv in invoices
    )
    body = f"""
    <div class="card">
      <h2>Welcome, {session['username']}</h2>
      <p>Your invoices:</p>
      <table><tr><th>ID</th><th>Item</th><th></th></tr>{rows}</table>
      <p style="margin-top:20px"><a href="/logout">Log out</a></p>
    </div>
    """
    return page(body)


@app.route("/invoice/<int:invoice_id>")
def view_invoice(invoice_id):
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    # --- THE BUG ---
    # This looks up an invoice by id and shows it to whoever is logged in,
    # with no check that invoice.user_id == session["user_id"].
    # That missing check is the entire vulnerability.
    inv = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    conn.close()

    if not inv:
        return page('<div class="card"><p class="err">No invoice with that ID.</p>'
                     '<p><a href="/dashboard">Back</a></p></div>'), 404

    flag_line = ""
    if "FLAG{" in inv["amount"]:
        flag_line = f'<p class="flag">{inv["amount"]}</p>'
        amount_display = flag_line
    else:
        amount_display = f'<p>{inv["amount"]}</p>'

    body = f"""
    <div class="card">
      <h2>Invoice #{inv['id']}</h2>
      <p><b>Item:</b> {inv['item']}</p>
      <p><b>Amount:</b></p>
      {amount_display}
      <p style="margin-top:20px"><a href="/dashboard">Back to dashboard</a></p>
    </div>
    """
    return page(body)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"InvoicePortal running — http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
