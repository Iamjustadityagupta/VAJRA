from flask import Flask, request

app = Flask(__name__)


class FakeDB:
    """Tiny in-memory DB simulator used only for the VAJRA demo.

    It intentionally models the security boundary we want to demonstrate:
    string-built SQL is vulnerable, while parameterized SQL treats the input
    as data.
    """

    def execute(self, query, params=None):
        # Vulnerable form: attacker-controlled text becomes part of the query.
        if params is None and ("' OR '1'='1" in query or " OR " in query.upper()):
            return "ALL USERS"
        return "USER RESULT"


db = FakeDB()


@app.get('/user')
def user():
    name = request.args.get('name', '')
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(query)
