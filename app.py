# app.py — cleaned & ready to paste
import os
import smtplib
import requests
from email.mime.text import MIMEText
from datetime import datetime, date, timedelta
from collections import defaultdict

from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
import google.oauth2.id_token

from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# -------------------------------------------------
# Flask app setup
# -------------------------------------------------
app = Flask(__name__)
# use SECRET_KEY from environment (set this in Render / locally)
app.secret_key = os.getenv("SECRET_KEY", "change_this_for_dev_only")

# -------------------------------------------------
# SQLite DB configuration
# -------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "billsmart.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Migrate should be initialized after app & db
from flask_migrate import Migrate
migrate = Migrate(app, db)

# -------------------------------------------------
# Email configuration (use env vars)
# -------------------------------------------------
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")  # your gmail
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")  # app password

# -------------------------------------------------
# WhatsApp Cloud API configuration (env vars)
# -------------------------------------------------
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID")  # numeric id (no plus)
# Note: DO NOT store user numbers here — store per-user in DB (User.phone)

# -------------------------------------------------
# Google OAuth2 config (prefer env)
# -------------------------------------------------
GOOGLE_CLIENT_ID = os.getenv(
    "GOOGLE_CLIENT_ID",
    "736005593161-e13hjvcqlsepnpgrda18n6jl8f2rbnlp.apps.googleusercontent.com",
)
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = os.getenv("OAUTHLIB_INSECURE_TRANSPORT", "1")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:5000/google/callback")

# -------------------------------------------------
# Helper: Email send functions
# -------------------------------------------------
def send_email_raw(to_email: str, subject: str, body: str):
    """Generic plain-text email sender using configured SMTP credentials."""
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        app.logger.error("Email credentials missing (EMAIL_ADDRESS/EMAIL_PASSWORD)")
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
        app.logger.info("Email sent to %s", to_email)
        return True
    except Exception as e:
        app.logger.exception("Failed to send email to %s: %s", to_email, e)
        return False


def send_welcome_email(to_email, name):
    subject = "Welcome to BillSmart 🎉"
    body = f"""Hi {name},

👋 Welcome to BillSmart!
You're now part of our smart billing system 😊
Start adding your bills and we'll take care of reminders.

Regards,
BillSmart Team
"""
    return send_email_raw(to_email, subject, body)


def send_email_reminder(user_email, user_name, bill):
    subject = f"Reminder: {bill.title} due on {bill.due_date}"
    body = f"""Hi {user_name},

This is a reminder for your upcoming bill:

Bill: {bill.title}
Amount: ₹{bill.amount}
Due Date: {bill.due_date}

Please pay on time to avoid late fees.

— BillSmart
"""
    return send_email_raw(user_email, subject, body)


# -------------------------------------------------
# Helper: WhatsApp send (simple text)
# -------------------------------------------------
def send_whatsapp_message(phone_number: str, message_text: str) -> bool:
    """
    Send a simple text WhatsApp message via Facebook Cloud API.
    phone_number should be in international format, e.g. "9198XXXXXXXX" or "+9198XXXXXXXX".
    """
    token = WHATSAPP_TOKEN or os.getenv("WHATSAPP_TOKEN")
    phone_id = PHONE_NUMBER_ID or os.getenv("PHONE_NUMBER_ID")
    if not token or not phone_id:
        app.logger.error("WhatsApp credentials missing")
        return False

    # ensure phone format — remove spaces
    phone_number_clean = phone_number.replace(" ", "")
    # Remove leading plus if present (Cloud API accepts without +)
    if phone_number_clean.startswith("+"):
        phone_number_clean = phone_number_clean[1:]

    url = f"https://graph.facebook.com/v17.0/{phone_id}/messages"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": phone_number_clean,
        "type": "text",
        "text": {"body": message_text}
    }

    try:
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        app.logger.info("WhatsApp send status %s -> %s", r.status_code, r.text)
        return r.status_code in (200, 201)
    except Exception as e:
        app.logger.exception("WhatsApp request failed: %s", e)
        return False


# -------------------------------------------------
# Models
# -------------------------------------------------
from flask_login import UserMixin

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20), nullable=True)  # stored as international string e.g. 9198...
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Bill(db.Model):
    __tablename__ = "bills"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(50), default="pending")  # pending / paid
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref=db.backref("bills", lazy=True))


# -------------------------------------------------
# Helper: login check (decorator)
# -------------------------------------------------
def login_required(f):
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapper


# -------------------------------------------------
# Routes (index, register, login, logout, dashboard)
# -------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        # Basic validation
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered!", "danger")
            return redirect(url_for("register"))

        # Basic phone validate (digits, length)
        phone_digits = "".join([c for c in phone if c.isdigit()])
        if len(phone_digits) < 10:
            flash("Enter a valid phone number (10+ digits).", "danger")
            return redirect(url_for("register"))

        # Hash password
        hashed_password = generate_password_hash(password)

        # Save user
        new_user = User(
            name=name,
            email=email,
            phone=phone_digits,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        # Send welcome email (best-effort)
        try:
            send_welcome_email(new_user.email, new_user.name)
        except Exception:
            app.logger.exception("Failed to send welcome email")

        # Send welcome WhatsApp (best-effort)
        try:
            if new_user.phone:
                send_whatsapp_message(
                    new_user.phone,
                    f"Hi {new_user.name}, 👋 Welcome to BillSmart! You're now part of our smart billing system 😊"
                )
        except Exception:
            app.logger.exception("Failed to send welcome WhatsApp")

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    # If GET request → show form
    return render_template("register.html")


@app.route("/login/google")
def login_google():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": os.getenv("GOOGLE_CLIENT_ID", GOOGLE_CLIENT_ID),
                "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [GOOGLE_REDIRECT_URI]
            }
        },
        scopes=[
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "openid"
        ]
    )

    flow.redirect_uri = GOOGLE_REDIRECT_URI
    auth_url, state = flow.authorization_url(
        prompt="consent",
        access_type="offline",
        include_granted_scopes="true"
    )

    session["state"] = state
    return redirect(auth_url)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["user_name"] = user.name
            flash(f"Welcome back, {user.name}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    bills = Bill.query.filter_by(user_id=user_id).order_by(Bill.due_date).all()
    total_amount = sum(b.amount for b in bills) if bills else 0
    pending_bills = [b for b in bills if b.status == "pending"]
    paid_bills = [b for b in bills if b.status == "paid"]

    # -------- Category-wise totals --------
    category_totals = defaultdict(float)
    for b in bills:
        category_totals[b.category] += b.amount

    category_labels = list(category_totals.keys())
    category_values = [category_totals[c] for c in category_labels]

    # -------- Month-wise totals (by bill due date) --------
    month_totals = defaultdict(float)
    for b in bills:
        if b.due_date:
            key = b.due_date.strftime("%b %Y")  # e.g., "Nov 2025"
            month_totals[key] += b.amount

    def month_key(label):
        return datetime.strptime(label, "%b %Y")

    month_labels = sorted(month_totals.keys(), key=month_key) if month_totals else []
    month_values = [month_totals[m] for m in month_labels]

    return render_template(
        "dashboard.html",
        user=user,
        bills=bills,
        total_amount=total_amount,
        pending_count=len(pending_bills),
        paid_count=len(paid_bills),
        category_labels=category_labels,
        category_values=category_values,
        month_labels=month_labels,
        month_values=month_values,
    )


# -------------------------------------------------
# Email reminders (upcoming bills) - user can trigger
# -------------------------------------------------
@app.route("/send_reminders")
@login_required
def send_reminders():
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    today = date.today()
    upcoming = today + timedelta(days=2)

    bills = Bill.query.filter(
        Bill.user_id == user_id,
        Bill.status.ilike("pending")
    ).order_by(Bill.due_date).all()

    if not bills:
        flash("No upcoming pending bills in the next 2 days.", "info")
        return redirect(url_for("dashboard"))

    lines = [f"Hi {user.name},", "", "Here are your upcoming bills:"]
    for b in bills:
        lines.append(f"- {b.title} | ₹{b.amount:.2f} | Due: {b.due_date}")

    lines.append("")
    lines.append("Please pay them on time to avoid late fees.")
    body = "\n".join(lines)

    try:
        send_email_raw(user.email, "Upcoming Bill Reminders - BillSmart", body)
        flash("Email reminders sent successfully! 📧", "success")
    except Exception as e:
        app.logger.exception("EMAIL ERROR:")
        flash("Error sending email reminders. Check email configuration.", "danger")

    return redirect(url_for("dashboard"))


# -------------------------------------------------
# WhatsApp reminders (upcoming bills) - user can trigger
# -------------------------------------------------
@app.route("/send_whatsapp")
@login_required
def send_whatsapp():
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    # get only pending bills
    bills = Bill.query.filter_by(user_id=user_id, status="pending").order_by(Bill.due_date).all()

    if not bills:
        flash("No pending bills available to send reminder.", "info")
        return redirect(url_for("dashboard"))

    for b in bills:
        app.logger.info("SENDING: %s %s %s %s", user.name, b.title, b.amount, b.due_date)

        # Compose a text message (simple)
        whatsapp_text = (
            f"Hi {user.name},\n"
            f"Reminder: Your bill *{b.title}* of ₹{b.amount} is due on {b.due_date}.\n"
            f"Please pay on time. - BillSmart"
        )

        # Use user's phone (stored in user.phone)
        if not user.phone:
            app.logger.warning("User %s has no phone number, skipping WhatsApp send.", user.email)
            continue

        sent = send_whatsapp_message(user.phone, whatsapp_text)
        if not sent:
            app.logger.error("Failed to send WhatsApp to %s", user.phone)

    flash("WhatsApp bill reminders sent successfully! 📱", "success")
    return redirect(url_for("dashboard"))


# -------------------------------------------------
# Bill CRUD (add/edit/delete/list)
# -------------------------------------------------
@app.route("/add_bill", methods=["GET", "POST"])
@login_required
def add_bill():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        amount_raw = request.form.get("amount", "0").strip()
        category = request.form.get("category", "").strip()
        due_date_str = request.form.get("due_date", "").strip()

        if not title or not amount_raw or not category or not due_date_str:
            flash("All fields are required.", "danger")
            return redirect(url_for("add_bill"))

        try:
            amount = float(amount_raw)
        except ValueError:
            flash("Amount must be a number.", "danger")
            return redirect(url_for("add_bill"))

        try:
            due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date()
        except ValueError:
            flash("Invalid date format.", "danger")
            return redirect(url_for("add_bill"))

        user_id = session.get("user_id")
        new_bill = Bill(
            title=title,
            amount=amount,
            category=category,
            due_date=due_date,
            user_id=user_id
        )

        db.session.add(new_bill)
        db.session.commit()

        flash("Bill added successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_bill.html")


@app.route("/bills")
@login_required
def bills():
    user_id = session.get("user_id")
    bills = Bill.query.filter_by(user_id=user_id).order_by(Bill.due_date).all()
    return render_template("bills.html", bills=bills)


@app.route("/edit_bill/<int:bill_id>", methods=["GET", "POST"])
@login_required
def edit_bill(bill_id):
    bill = Bill.query.get_or_404(bill_id)

    if request.method == "POST":
        bill.title = request.form.get("title", "").strip()
        amount_raw = request.form.get("amount", "0").strip()
        bill.category = request.form.get("category", "").strip()
        due_date_str = request.form.get("due_date", "").strip()
        bill.status = request.form.get("status", "pending")

        try:
            bill.amount = float(amount_raw)
        except ValueError:
            flash("Amount must be a number.", "danger")
            return redirect(url_for("edit_bill", bill_id=bill_id))

        try:
            bill.due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date()
        except ValueError:
            flash("Invalid date format.", "danger")
            return redirect(url_for("edit_bill", bill_id=bill_id))

        db.session.commit()
        flash("Bill updated successfully!", "success")
        return redirect(url_for("bills"))

    return render_template("edit_bill.html", bill=bill)


@app.route("/delete_bill/<int:bill_id>")
@login_required
def delete_bill(bill_id):
    bill = Bill.query.get_or_404(bill_id)
    db.session.delete(bill)
    db.session.commit()
    flash("Bill deleted successfully!", "info")
    return redirect(url_for("bills"))


# -------------------------------
# Export Bills to PDF and Excel
# -------------------------------
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from io import BytesIO
import pandas as pd

@app.route("/export_pdf")
@login_required
def export_pdf():
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    bills = Bill.query.filter_by(user_id=user_id).order_by(Bill.due_date).all()

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, 820, f"BillSmart - Bill Report for {user.name}")

    pdf.setFont("Helvetica", 12)
    y = 780
    for bill in bills:
        line = f"{bill.title} | ₹{bill.amount} | {bill.category} | {bill.due_date} | {bill.status}"
        pdf.drawString(50, y, line)
        y -= 20
        if y < 50:
            pdf.showPage()
            y = 820

    pdf.save()
    buffer.seek(0)

    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=bills_report.pdf'
    return response


@app.route("/export_excel")
@login_required
def export_excel():
    user_id = session.get("user_id")
    bills = Bill.query.filter_by(user_id=user_id).order_by(Bill.due_date).all()

    rows = [{
        "Title": b.title,
        "Amount": b.amount,
        "Category": b.category,
        "Due Date": b.due_date,
        "Status": b.status
    } for b in bills]

    df = pd.DataFrame(rows)
    output = BytesIO()
    df.to_excel(output, index=False)
    output.seek(0)

    response = make_response(output.getvalue())
    response.headers['Content-Type'] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    response.headers['Content-Disposition'] = "attachment; filename=bills_report.xlsx"
    return response


@app.route("/google/callback")
def login_google_callback():
    state = session.get("state")
    incoming_state = request.args.get("state")

    if not state or state != incoming_state:
        session.pop("state", None)
        return redirect(url_for("login_google"))

    # Build Flow from ENV variables (NO JSON FILE)
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [GOOGLE_REDIRECT_URI]
            }
        },
        scopes=[
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "openid"
        ],
        state=state
    )

    flow.redirect_uri = GOOGLE_REDIRECT_URI
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials

    request_session = requests.Session()
    token_request = google.auth.transport.requests.Request(session=request_session)
    id_info = google.oauth2.id_token.verify_oauth2_token(
        credentials._id_token,
        token_request,
        os.getenv("GOOGLE_CLIENT_ID")
    )

    google_email = id_info.get("email")
    google_name = id_info.get("name")

    # Check if user exists
    user = User.query.filter_by(email=google_email).first()

    if not user:
        user = User(
            name=google_name,
            email=google_email,
            password=generate_password_hash("GOOGLE_AUTH")
        )
        db.session.add(user)
        db.session.commit()

    session["user_id"] = user.id
    session["user_name"] = user.name
    flash(f"Logged in with Google as {user.name}", "success")

    return redirect(url_for("dashboard"))


# -------------------------------------------------
# App entry
# -------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
