from flask import Flask, request, jsonify

from models import User, db

app = Flask(__name__)


@app.route("/users", methods=["POST"])
def create_user():
    user = User(**request.json)  # LSA-EXPECT:MASS
    db.session.add(user)
    db.session.commit()
    return jsonify(id=user.id)


@app.route("/users/<int:uid>/name", methods=["POST"])
def rename(uid):
    user = User.query.get(uid)
    user.name = request.json["name"]  # LSA-EXPECT:SAFE-MASS
    db.session.commit()
    return jsonify(ok=True)


@app.route("/users/<int:uid>", methods=["PATCH"])
def patch(uid):
    user = User.query.get(uid)
    for key, value in request.json.items():  # LSA-EXPECT:MASS
        setattr(user, key, value)
    db.session.commit()
    return jsonify(ok=True)
