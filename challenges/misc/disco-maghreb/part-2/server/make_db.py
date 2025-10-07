import sqlite3

conn = sqlite3.connect("songs.db")
c = conn.cursor()

c.execute("DROP TABLE IF EXISTS songs")
c.execute("DROP TABLE IF EXISTS secret")

c.execute("CREATE TABLE songs (id INTEGER PRIMARY KEY, artist TEXT, title TEXT)")
c.execute("CREATE TABLE secret (flag TEXT)")

songs = [
    ("Cheb Khaled", "Didi"),
    ("Cheb Khaled", "Aïcha"),
    ("Cheb Mami", "Desert Rose"),
    ("Cheb Mami", "Meli Meli"),
    ("Cheb Hasni", "El Visa"),
    ("Cheb Hasni", "Ma Hachak"),
    ("Cheb Bilal", "Ghorba"),
    ("Cheb Bilal", "Sghira"),
    ("Faudel", "Tellement NBR"),
    ("Faudel", "Mon Pays"),
    ("Cheikha Remitti", "Sidi Mansour"),
    ("Cheikha Remitti", "Harramt Ahebbak"),
    ("Cheikha Remitti", "Nouar"),
]

c.executemany("INSERT INTO songs (artist, title) VALUES (?, ?)", songs)

c.execute("INSERT INTO secret (flag) VALUES ('flag-rai_n3v3r_d135-Yj60e72N')")

conn.commit()
conn.close()
