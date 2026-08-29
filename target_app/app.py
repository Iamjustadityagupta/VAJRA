from flask import Flask, request, jsonify
import sqlite3
import subprocess

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
    conn.executemany(
        "INSERT INTO users (name) VALUES (?)",
        [("alice",), ("bob",), ("admin",)],
    )
    return conn


@app.get("/user")
def user():
    name = request.args.get("name", "")

    # INTENTIONALLY VULNERABLE: SQL injection.
    query = "SELECT id, name FROM users WHERE name = '" + name + "'"
    rows = get_db().execute(query).fetchall()

    return jsonify({"count": len(rows), "users": [dict(row) for row in rows]})


@app.get("/ping")
def ping():
    host = request.args.get("host", "localhost")

    # INTENTIONALLY VULNERABLE: command injection.
    command = "echo PING " + host
    output = subprocess.check_output(command, shell=True, text=True, timeout=3)

    return jsonify({"output": output.strip()})
