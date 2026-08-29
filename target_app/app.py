from flask import Flask, request, jsonify
import sqlite3

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
    db = get_db()

    # INTENTIONALLY VULNERABLE: user input is concatenated into SQL.
    query = "SELECT id, name FROM users WHERE name = '" + name + "'"
    rows = db.execute(query).fetchall()

    return jsonify({"count": len(rows), "users": [dict(row) for row in rows]})
