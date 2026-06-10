import hashlib
import sqlite3


def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()
