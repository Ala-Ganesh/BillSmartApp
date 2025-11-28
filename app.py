# -------------------------------------------------
# app.py — FINAL & ERROR-FREE VERSION
# -------------------------------------------------

import os
import smtplib
import requests
from email.mime.text import MIMEText
from datetime import datetime, date, timedelta
from collections import defaultdict
from dotenv import load_dotenv
load_dotenv()
print("SECRET KEY LOADED:", os.getenv("SECRET_KEY"))



from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
import google.oauth2.id_token

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# -------------------------------------------------
# Flask app initialization
# -------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "devsecret")

# -------------------------------------------------
# Database setup
# -------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "sqlite:///" + os.path.join(BASE_DIR, "billsmart.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -------------------------------------------------
# DB Migration
# -------------------------------------------------
from flask_migrate import Migrate
migrate = Migrate(app, db)

# -------------------------------------------------
# Environment Variables
# -------------------------------------------------
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")


os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


# -------------------------------------------------
# LOGIN REQUIRED DECORATOR
# -------------------------------------------------
def login_required(f):
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first!", "warning")
            return redirect("/login")
        return f(*args, **kwargs)

    return wrapper


# -------------------------------------------------
# EMAIL HELPERS
# -------------------------------------------------
def send_email_raw(to_email: str, subject: str, body: str):
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print("❌ Email credentials missing")
        return False

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email

    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, [to_email], msg.as_string())
        print("📧 Email sent:", to_email)
        return True
    except Exception as e:
        print("Email Error:", e)
        return False


def send_welcome_email(email, name):
    subject = "Welcome to BillSmart 🎉"
    body = f"""
Hi {name},

Welcome to BillSmart! We're happy to have you 😊

Regards,
BillSmart Team
"""
    send_email_raw(email, subject, body)


# -------------------------------------------------
# WHATSAPP SENDER
# -------------------------------------------------
def send_whatsapp_message(phone_number: str, text: str) -> bool:
    if not WHATSAPP_TOKEN or not PHONE_NUMBER_ID:
        print("❌ Missing WhatsApp credentials")
        return False

    phone = phone_number.replace(" ", "")
    if phone.startswith("+"):
        phone = phone[1:]
    if len(phone) == 10:
        phone = "91" + phone

    url = f"https://graph.facebook.com/v17.0/{PHONE_NUMBER_ID}/messages"
    payload = {
        "messaging_product": "whatsapp",
        "to": phone,
        "type": "text",
        "text": {"body": text}
    }
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        r = requests.post(url, json=payload, headers=headers)
        print("WA Response:", r.status_code, r.text)
        return r.status_code in (200, 201)
    except Exception as e:
        print("WA Error:", e)
        return False


# -------------------------------------------------
# MODELS
# -------------------------------------------------
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Bill(db.Model):
    __tablename__ = "bills"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(50), default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="bills")


# -------------------------------------------------
# HOME
# -------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect("/dashboard")
    return redirect("/login")


# -------------------------------------------------
# REGISTER
# -------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"].lower()
        phone = request.form["phone"]
        password = request.form["password"]
        confirm = request.form["confirm_password"]

        if password != confirm:
            flash("Passwords do not match!", "danger")
            return redirect("/register")

        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect("/register")

        digits = "".join([c for c in phone if c.isdigit()])
        if len(digits) < 10:
            flash("Invalid phone number!", "danger")
            return redirect("/register")

        new_user = User(
            name=name,
            email=email,
            phone=digits,
            password=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()

        send_welcome_email(email, name)
        send_whatsapp_message(digits, f"Hi {name}, 👋 Welcome to BillSmart!")

        flash("Registration successful!", "success")
        return redirect("/login")

    return render_template("register.html")


# -------------------------------------------------
# LOGIN
# -------------------------------------------------
# -------------------------------------------------
# LOGIN (CLEAN + FIXED INDENTATION)
# -------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].lower()
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["user_name"] = user.name
            session["user_phone"] = user.phone   # <-- Correctly indented
            return redirect("/dashboard")

        flash("Invalid email or password!", "danger")
        return redirect("/login")

    return render_template("login.html")



# -------------------------------------------------
# GOOGLE LOGIN
# -------------------------------------------------
@app.route("/login/google")
def login_google():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [GOOGLE_REDIRECT_URI]
            }
        },
        scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile"
        ]
    )

    flow.redirect_uri = GOOGLE_REDIRECT_URI

    auth_url, state = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        include_granted_scopes="true"
    )

    session["state"] = state
    return redirect(auth_url)


# -------------------------------------------------
# GOOGLE CALLBACK (CLEANED & FIXED)
# -------------------------------------------------
@app.route("/google/callback")
def login_google_callback():
    state = session.get("state")
    incoming_state = request.args.get("state")

    if not state or state != incoming_state:
        flash("OAuth state mismatch. Please try again.", "danger")
        return redirect("/login")

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [GOOGLE_REDIRECT_URI],
            }
        },
        scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile"
        ],
        state=state,
    )

    flow.redirect_uri = GOOGLE_REDIRECT_URI

    try:
        flow.fetch_token(authorization_response=request.url)
    except Exception as e:
        app.logger.error("Token fetch failed: %s", e)
        flash("Google Login Failed. Try again.", "danger")
        return redirect("/login")

    # Verify ID Token
    token_request = google.auth.transport.requests.Request()
    try:
        idinfo = google.oauth2.id_token.verify_oauth2_token(
            flow.credentials._id_token,
            token_request,
            GOOGLE_CLIENT_ID
        )
    except Exception as e:
        app.logger.error("ID Token verification failed: %s", e)
        flash("Could not verify Google token.", "danger")
        return redirect("/login")

    google_email = idinfo.get("email")
    google_name = idinfo.get("name")

    if not google_email:
        flash("Google did not return email!", "danger")
        return redirect("/login")

    user = User.query.filter_by(email=google_email).first()

    if not user:
        user = User(
            name=google_name,
            email=google_email,
            password=generate_password_hash("GOOGLE_USER"),
        )
        db.session.add(user)
        db.session.commit()

    session["user_id"] = user.id
    session["user_name"] = user.name
    session["user_phone"] = user.phone  # <- added

    flash(f"Logged in as {user.name}", "success")
    return redirect("/dashboard")




# -------------------------------------------------
# LOGOUT
# -------------------------------------------------
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect("/login")


# -------------------------------------------------
# DASHBOARD
# -------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    user = User.query.get(session["user_id"])
    bills = Bill.query.filter_by(user_id=user.id).order_by(Bill.due_date).all()

    # --------------------------------------
    # PHONE ALERT LOGIC (Correct Indentation)
    # --------------------------------------
    show_phone_alert = False
    if not user.phone:
        show_phone_alert = True

    total_amount = sum(b.amount for b in bills) if bills else 0

    # Category totals
    category_totals = defaultdict(float)
    for b in bills:
        category_totals[b.category] += b.amount

    # Month totals
    month_totals = defaultdict(float)
    for b in bills:
        key = b.due_date.strftime("%b %Y")
        month_totals[key] += b.amount

    return render_template(
        "dashboard.html",
        user=user,
        bills=bills,
        total_amount=total_amount,
        category_labels=list(category_totals.keys()),
        category_values=list(category_totals.values()),
        month_labels=list(month_totals.keys()),
        month_values=list(month_totals.values()),
        show_phone_alert=show_phone_alert    # <-- MUST PASS THIS
    )



# -------------------------------------------------
# TEST WHATSAPP
# -------------------------------------------------
@app.route("/test/whatsapp")
def test_whatsapp():
    send_whatsapp_message("+919948190328", "BillSmartApp WhatsApp Reminder Test ✔️")
    return "WhatsApp test sent!"


# -------------------------------------------------
# LIST BILLS
# -------------------------------------------------
@app.route("/bills")
@login_required
def bills():
    user_id = session["user_id"]
    all_bills = Bill.query.filter_by(user_id=user_id).order_by(Bill.due_date).all()
    return render_template("bills.html", bills=all_bills)


# -------------------------------------------------
# ADD BILL
# -------------------------------------------------
# -------------------------------------------------
# ADD BILL
# -------------------------------------------------
@app.route("/add_bill", methods=["GET", "POST"])
@login_required
def add_bill():
    if request.method == "POST":
        new_bill = Bill(
            title=request.form["title"],
            amount=float(request.form["amount"]),
            category=request.form["category"],
            due_date=datetime.strptime(request.form["due_date"], "%Y-%m-%d").date(),
            user_id=session["user_id"]
        )

        db.session.add(new_bill)
        db.session.commit()

        # SEND WHATSAPP BILL-ADDED MESSAGE
        user = User.query.get(session["user_id"])
        if user.phone:
            send_whatsapp_message(
                user.phone,
                f"🎉 Bill Added Successfully!\n\n"
                f"📌 {new_bill.title}\n"
                f"💰 Amount: ₹{new_bill.amount}\n"
                f"📅 Due Date: {new_bill.due_date}\n\n"
                f"Thanks for using BillSmart!"
            )

        flash("Bill added!", "success")
        return redirect("/dashboard")

    return render_template("add_bill.html")


# -------------------------------------------------
# EDIT BILL
# -------------------------------------------------
# -------------------------------------------------
# EDIT BILL
# -------------------------------------------------
@app.route("/edit_bill/<int:bill_id>", methods=["GET", "POST"])
@login_required
def edit_bill(bill_id):
    bill = Bill.query.get_or_404(bill_id)

    if request.method == "POST":
        bill.title = request.form["title"]
        bill.amount = float(request.form["amount"])
        bill.category = request.form["category"]
        bill.due_date = datetime.strptime(request.form["due_date"], "%Y-%m-%d").date()

        db.session.commit()

               # SEND WHATSAPP BILL-UPDATED MESSAGE
        user = User.query.get(session["user_id"])
        if user.phone:
            send_whatsapp_message(
                user.phone,
                f"✏️ Bill Updated Successfully!\n\n"
                f"📌 {bill.title}\n"
                f"💰 Amount: ₹{bill.amount}\n"
                f"📅 Due Date: {bill.due_date}\n"
                f"📌 Status: {bill.status.capitalize()}\n\n"
                f"Thanks for using BillSmart!"
            )


        flash("Bill updated!", "success")
        return redirect("/bills")

    return render_template("edit_bill.html", bill=bill)

# -------------------------------------------------
# DELETE BILL
# -------------------------------------------------
@app.route("/delete_bill/<int:bill_id>", methods=["POST", "GET"])
@login_required
def delete_bill(bill_id):
    bill = Bill.query.get_or_404(bill_id)

    db.session.delete(bill)
    db.session.commit()

    flash("Bill deleted!", "success")
    return redirect("/bills")




# -------------------------------------------------
# EMAIL REMINDERS
# -------------------------------------------------
@app.route("/send_reminders")
@login_required
def send_reminders():
    user_id = session["user_id"]
    user = User.query.get(user_id)

    today = date.today()
    next_2 = today + timedelta(days=2)

    bills = Bill.query.filter(
        Bill.user_id == user_id,
        Bill.status == "pending",
        Bill.due_date <= next_2
    ).all()

    if not bills:
        flash("No upcoming bills!", "info")
        return redirect("/dashboard")

    message = f"Hi {user.name},\n\nYour upcoming bills:\n"
    for b in bills:
        message += f"- {b.title} | ₹{b.amount} | Due: {b.due_date}\n"

    send_email_raw(user.email, "BillSmart Reminder", message)

    flash("Email reminders sent!", "success")
    return redirect("/dashboard")


# -------------------------------------------------
# WHATSAPP REMINDERS
# -------------------------------------------------
@app.route("/send_whatsapp")
@login_required
def send_whatsapp():
    user = User.query.get(session["user_id"])
    bills = Bill.query.filter_by(user_id=user.id, status="pending").all()

    if not bills:
        flash("No pending bills!", "info")
        return redirect("/dashboard")

    for b in bills:
        send_whatsapp_message(
            user.phone,
            f"⏰ Reminder from BillSmart!\n\nBill: {b.title}\nAmount: ₹{b.amount}\nDue: {b.due_date}"
        )

    flash("WhatsApp reminders sent!", "success")
    return redirect("/dashboard")



# -------------------------------------------------
# EXPORTS FOR daily_reminder.py
# -------------------------------------------------
__all__ = [
    "app",
    "db",
    "User",
    "Bill",
    "send_email_raw",
    "send_whatsapp_message",
]
# -------------------------------------------------
# UPDATE PHONE NUMBER (NEW FEATURE)
# -------------------------------------------------
@app.route("/update_phone", methods=["GET", "POST"])
@login_required
def update_phone():
    user = User.query.get(session["user_id"])

    if request.method == "POST":
        phone = request.form["phone"]
        digits = "".join([c for c in phone if c.isdigit()])  # keep numbers only

        if len(digits) < 10:
            flash("Invalid phone number!", "danger")
            return redirect("/update_phone")

        # Save phone number
        user.phone = digits
        db.session.commit()

        # Update session
        session["user_phone"] = digits

        # Send WhatsApp greeting
        send_whatsapp_message(
            digits,
            f"👋 Hello {user.name}!\n\n"
            f"🎉 WhatsApp reminders are now activated!\n"
            f"You will now receive:\n"
            f"• Bill added confirmations\n"
            f"• Upcoming bill reminders\n"
            f"• Daily reminders (if enabled)\n\n"
            f"Thank you for using BillSmart 😊"
        )

        flash("Mobile number added successfully!", "success")
        return redirect("/dashboard")

    return render_template("update_phone.html", user=user)





# -------------------------------------------------
# RUN APP — FINAL BLOCK (ONLY ONCE)
# -------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
