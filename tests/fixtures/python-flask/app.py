from flask import Flask, request, session, jsonify
from flask_login import login_required, current_user
import db

app = Flask(__name__)


@app.route('/orders/<int:order_id>')
@login_required
def order(order_id):
    cur = db.conn().cursor()
    cur.execute("SELECT * FROM orders WHERE id = %s" % order_id)  # LSA-EXPECT:SAFE-SQL LSA-EXPECT:BOLA
    return jsonify(cur.fetchone())


@app.route('/orders/mine/<int:order_id>')
@login_required
def my_order(order_id):
    cur = db.conn().cursor()
    cur.execute("SELECT * FROM orders WHERE id = %s AND user_id = %s", (order_id, current_user.id))  # LSA-EXPECT:SAFE-SQL-NOFLAG LSA-EXPECT:SAFE-BOLA
    return jsonify(cur.fetchone())


@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    q = request.args.get('q', '')
    cur = db.conn().cursor()
    cur.execute(f"SELECT * FROM products WHERE name LIKE '%{q}%'")  # LSA-EXPECT:SQLI
    return jsonify(cur.fetchall())
