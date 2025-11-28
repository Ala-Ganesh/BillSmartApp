from app import app, db

with app.app_context():
    with db.engine.connect() as conn:
        conn.execute(db.text("ALTER TABLE users ADD COLUMN phone TEXT"))
        print("Phone column added successfully!")
