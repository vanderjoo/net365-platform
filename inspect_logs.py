import sqlite3
import database as db

conn = db.get_db_connection()
rows = conn.execute("PRAGMA database_list").fetchall()
print("App is connected to:")
for r in rows:
    print(" ", tuple(r))   # ('main', '/full/path/to/file.db', '')
conn.close()