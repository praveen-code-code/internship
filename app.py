from flask import Flask, request, jsonify
import psycopg2
from flask_bcrypt import Bcrypt
import jwt
import datetime

app = Flask(__name__)

bcrypt = Bcrypt(app)


# DATABASE CONFIG
DB_HOST = "localhost"
DB_NAME = "postgres"
DB_USER = "postgres"
DB_PASSWORD = "1616"


def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )


# CREATE USERS TABLE
def create_users_table():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users_db(
            user_id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        );
    """)

    connection.commit()

    cursor.close()
    connection.close()


# CREATE NOTE TABLE
def create_note_table():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS note(
            note_id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users_db(user_id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            discription TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    connection.commit()

    cursor.close()
    connection.close()


create_users_table()
create_note_table()


# SECRET KEY
SECRET_KEY = "this is my secret key this is my secret key!!"


# CREATE JWT
def create_jwt(user_id, username):

    payload = {
        "user_id": user_id,
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return token


# VERIFY JWT
def verify_jwt(token):

    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return data

    except:
        return None


# SIGNUP API
@app.route("/signup", methods=["POST"])
def signup():

    username = request.json["username"]
    email = request.json["email"]
    password = request.json["password"]

    if not username or not email or not password:
        return jsonify({"error": "All fields required"}), 400

    connection = get_db_connection()
    cursor = connection.cursor()

    # CHECK EMAIL EXISTS
    cursor.execute("""
        SELECT * FROM users_db
        WHERE email = %s
    """, (email,))

    existing_user = cursor.fetchone()

    if existing_user:
        return jsonify({"error": "Email already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    cursor.execute("""
        INSERT INTO users_db(username,email,password)
        VALUES(%s,%s,%s)
        RETURNING user_id
    """, (username, email, hashed_password))

    user_id = cursor.fetchone()[0]

    connection.commit()

    cursor.close()
    connection.close()

    token = create_jwt(user_id, username)

    return jsonify({
        "message": "Signup successful",
        "token": token
    }), 201


# LOGIN API
@app.route("/login", methods=["POST"])
def login():

    email = request.json["email"]
    password = request.json["password"]

    if not email or not password:
        return jsonify({"error": "All fields required"}), 400

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT user_id, username, password
        FROM users_db
        WHERE email = %s
    """, (email,))

    user = cursor.fetchone()

    cursor.close()
    connection.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    user_id, username, hashed_password = user

    if not bcrypt.check_password_hash(hashed_password, password):
        return jsonify({"error": "Invalid password"}), 401

    token = create_jwt(user_id, username)

    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {
            "user_id": user_id,
            "username": username,
            "email": email
        }
    }), 200


# CREATE NOTE
@app.route("/create_note", methods=['POST'])
def create_note():

    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"error": "Token required"}), 401

    user_data = verify_jwt(token)

    if user_data is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    user_id = user_data["user_id"]

    title = request.json['title']
    discription = request.json['discription']

    if not title or not discription:
        return jsonify({"error": "All fields required"}), 400

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO note(user_id,title,discription)
        VALUES(%s,%s,%s);
    """, (user_id, title, discription))

    connection.commit()

    cursor.close()
    connection.close()

    return jsonify({
        "message": "Note created successfully",
        "user_id": user_id
    }), 201


# GET NOTE
@app.route("/get_note", methods=['GET'])
def get_note():

    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"error": "Token required"}), 401

    user_data = verify_jwt(token)

    if user_data is None:
        return jsonify({"error": "Invalid or expired token"}), 401

  

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT note_id,title,discription,created_at
        FROM note
        WHERE user_id = %s;
    """, (user_data["user_id"],))

    notes = cursor.fetchall()

    cursor.close()
    connection.close()

    return jsonify({
        "user_id":user_data["user_id"],
        "username": user_data["username"],
        "notes": [
            {
                "note_id": note[0],
                "title": note[1],
                "discription": note[2],
                "created_at": note[3]
            }
            for note in notes
        ]
    }), 200


# UPDATE NOTE
@app.route("/update_note/<int:note_id>", methods=['PUT'])
def update_note(note_id):

    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"error": "Token required"}), 401

    user_data = verify_jwt(token)

    if user_data is None:
        return jsonify({"error": "Invalid or expired token"}), 401

  

    title = request.json['title']
    discription = request.json['discription']

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM note
        WHERE note_id = %s AND user_id = %s
    """, (note_id, user_data["user_id"]))

    note = cursor.fetchone()

    if not note:
        return jsonify({"error": "Note not found"}), 404

    cursor.execute("""
        UPDATE note
        SET title = %s,
            discription = %s
        WHERE note_id = %s;
    """, (title, discription, note_id))

    connection.commit()

    cursor.close()
    connection.close()

    return jsonify({
        "message": "Note updated successfully"
    }), 200


# DELETE NOTE
@app.route("/delete_note/<int:note_id>", methods=['DELETE'])
def delete_note(note_id):

    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"error": "Token required"}), 401

    user_data = verify_jwt(token)

    if user_data is None:
        return jsonify({"error": "Invalid or expired token"}), 401

 

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM note
        WHERE note_id = %s AND user_id = %s
    """, (note_id,user_data["user_id"]))

    note = cursor.fetchone()

    if not note:
        return jsonify({"error": "Note not found"}), 404

    cursor.execute("""
        DELETE FROM note
        WHERE note_id = %s;
    """, (note_id,))

    connection.commit()

    cursor.close()
    connection.close()

    return jsonify({
        "message": "Note deleted successfully"
    }), 200


if __name__ == "__main__":
    app.run(debug=True)