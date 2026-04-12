import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Connect to the default postgres database to create our new one
conn = psycopg2.connect(
    dbname="postgres",
    user="postgres",
    password="the123",
    host="localhost",
    port=5433
)
conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
cur = conn.cursor()

try:
    cur.execute("CREATE DATABASE voice_ai;")
    print("Database 'voice_ai' created successfully.")
except Exception as e:
    print(f"Notice: {e}")

cur.close()
conn.close()

# Now connect to the new database and create tables
conn = psycopg2.connect(
    dbname="voice_ai",
    user="postgres",
    password="the123",
    host="localhost",
    port=5433
)
cur = conn.cursor()

with open("db/schema.sql", "r") as f:
    schema = f.read()

cur.execute(schema)
conn.commit()

cur.close()
conn.close()
print("Tables created successfully.")
