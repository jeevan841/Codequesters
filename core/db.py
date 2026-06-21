"""
core/db.py — Database connection pool (shared across all routers).
"""
from contextlib import contextmanager
from typing import Optional
import psycopg2.pool

# Populated at app startup via the lifespan event in app.py
db_pool: Optional[psycopg2.pool.SimpleConnectionPool] = None


@contextmanager
def get_db():
    """Borrow a connection from the pool and return it when done."""
    conn = db_pool.getconn()
    try:
        yield conn
    finally:
        db_pool.putconn(conn)
