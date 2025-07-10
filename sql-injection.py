"""
Demonstration of a Simple SQL Injection Vulnerability (for awareness ONLY)

- This script simulates a login form with a SQL injection vulnerability.
- DO NOT use insecure query patterns in production code.

Dependencies:
    Python standard library only.

Usage:
    python vulnerable_sql_injection_demo.py
"""

import sqlite3

def setup_db():
    # Create an in-memory SQLite database with one user
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    c.execute("CREATE TABLE users (username TEXT, password TEXT)")
    c.execute("INSERT INTO users VALUES ('admin', 'secret123')")
    conn.commit()
    return conn

def vulnerable_login(conn, username, password):
    # WARNING: This is intentionally vulnerable to SQL Injection!
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"Executing query: {query}")  # For demo purposes
    c = conn.cursor()
    c.execute(query)
    return c.fetchone() is not None

# Safe login function (not vulnerable to SQL injection)
# def safe_login(conn, username, password):
#     c = conn.cursor()
#     c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
#     return c.fetchone() is not None

def main():
    print("=== Vulnerable SQL Injection Demo ===")
    conn = setup_db()
    username = input("Username: ")
    password = input("Password: ")

    if vulnerable_login(conn, username, password):
        print("Login successful!")
    else:
        print("Login failed.")

    # Example of SQLi:
    # Username: admin
    # Password: ' OR '1'='1
    # This will bypass authentication!

if __name__ == "__main__":
    main()
