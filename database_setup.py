import sqlite3

def setup_database():
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()

    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    );
    """)

    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS feedback_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        query TEXT NOT NULL,
        predicted_label TEXT NOT NULL,
        actual_label TEXT DEFAULT NULL,
        ip_address TEXT NOT NULL  
        );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        position TEXT NOT NULL
    );
    """)

    cursor.executemany("""
    INSERT INTO employees (name, position) VALUES (?, ?);
    """, [
        ("Alice Johnson", "Software Engineer"),
        ("Bob Smith", "Data Scientist"),
        ("Charlie Brown", "Cybersecurity Analyst")
    ])

    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE NOT NULL
    );
    """)

    conn.commit()
    conn.close()
    print("✅ Database setup completed!")

if __name__ == "__main__":
    setup_database()

