"""
create_db.py — Bootstrap the PostgreSQL database and schema.

Reads all connection settings from environment variables (or a .env file).
Never hardcodes passwords.  Copy .env.example to .env and fill in real values
before running this script.

Usage:
    python create_db.py
"""

import os
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from dotenv import load_dotenv

load_dotenv()

# Required env vars — will raise a clear error if missing.
def _require(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"Environment variable '{name}' is required but not set. "
            "Copy .env.example to .env and fill in the values."
        )
    return value

DB_HOST = _require("DB_HOST")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_USER = _require("DB_USER")
DB_PASSWORD = _require("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME", "voice_ai")

# Step 1: Connect to the default 'postgres' database to create our app DB
conn = psycopg2.connect(
    dbname="postgres",
    user=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=int(DB_PORT),
)
conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
cur = conn.cursor()

try:
    cur.execute(f"CREATE DATABASE {DB_NAME};")
    print(f"Database '{DB_NAME}' created successfully.")
except Exception as e:
    print(f"Notice: {e}")

cur.close()
conn.close()

# Step 2: Connect to the new database and apply the schema
conn = psycopg2.connect(
    dbname=DB_NAME,
    user=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=int(DB_PORT),
)
cur = conn.cursor()

with open("db/schema.sql", "r") as f:
    schema = f.read()

cur.execute(schema)
conn.commit()

cur.close()
conn.close()
print("Tables created successfully.")
