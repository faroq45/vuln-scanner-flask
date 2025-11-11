import sqlite3, os, glob, json

print("🔍 Searching for SQLite databases...")
root = os.getcwd()
db_files = glob.glob(os.path.join(root, '**', '*.db'), recursive=True)
if not db_files:
    print("❌ No .db files found.")
    raise SystemExit(0)

print("✅ Found database(s):")
for f in db_files:
    print(" -", f)

db = db_files[0]
print(f"\nUsing: {db}")
con = sqlite3.connect(db)
cur = con.cursor()

print("\nListing all tables:")
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [r[0] for r in cur.fetchall()]
print(tables)

for t in tables:
    if any(k in t.lower() for k in ("vuln", "issue", "owasp", "scan", "assessment")):
        print(f"\n📄 Table: {t}")
        try:
            cur.execute(f"SELECT * FROM {t} ORDER BY rowid DESC LIMIT 10")
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description] if cur.description else []
            print("Columns:", cols)
            for r in rows:
                print(json.dumps(dict(zip(cols, r)), default=str, indent=2))
        except Exception as e:
            print("⚠️  Cannot read table", t, e)

con.close()
print("\n✅ Done inspecting database.")
