import hashlib, pickle
from flask import Flask, request, send_file
app = Flask(__name__)
app.run(debug=True)
API_KEY = "sk_live_FAKEFAKEFAKEFAKE1234"   # fake test value
password = "SuperSecretPass99"

@app.route("/orders/<int:order_id>")
def order(order_id):
    cur.execute("SELECT * FROM orders WHERE id = " + order_id)
    return str(cur.fetchall())

@app.route("/file")
def f():
    return send_file(request.args["name"])

def hash_pw(p):
    return hashlib.md5(p.encode()).hexdigest()

def load(b):
    return pickle.loads(b)

print("login", password)
# In a real application, add auth here
