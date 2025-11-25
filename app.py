from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
import google.oauth2.id_token
import requests
import os
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, date, timedelta
from collections import defaultdict

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# -------------------------------------------------
# Flask app & Database setup
# -------------------------------------------------
app = Flask(__name__)

# Secret key for sessions
app.secret_key = "billsmart-modern-secret"  # you can change this to any random string

# Google OAuth2 config
GOOGLE_CLIENT_ID = "736005593161-e13hjvcqlsepnpgrda18n6jl8f2rbnlp.apps.googleusercontent.com"
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
GOOGLE_REDIRECT_URI = "http://localhost:5000/google/callback"

# SQLite DB configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "billsmart.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -------------------------------------------------
# Email configuration
# -------------------------------------------------
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_ADDRESS = "alaganeshyadav@gmail.com"      # <-- your Gmail
EMAIL_PASSWORD = "mpds ihcv rtrj jfhc"          # <-- your App Password

# -------------------------------------------------
# WhatsApp Cloud API configuration
# -------------------------------------------------
WHATSAPP_TOKEN = "EAAT9oSJYbxwBQB3kgMAXoPZCquJKk9Py3lP2xqm460278jrhVLKNsy8RnaHWLZAdzQds0e5gPNmaJuCkERFjyDvuTrX4AEaAe16rdyAljZCZAV3PdbgQnzThFOZAhfCXiOs4DASghZAj7iIIRXRnkV6ZB4api8CnH6SaewbRVmZAvbvjufKvDsdww5AacwefPANc7wZDZD"
PHONE_NUMBER_ID = "921622914361686"
USER_WHATSAPP_NUMBER = "+919948190328"

def send_email(to_email: str, subject: str, body: str):
    """Helper to send plain text email."""
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email

    with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, [to_email], msg.as_string())



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
# Helper: login check
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
# Routes
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
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not name or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for("login"))

        hashed_password = generate_password_hash(password)
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")
@app.route("/login/google")
def login_google():
    flow = Flow.from_client_secrets_file(
        "client_secret_google.json",
        scopes=[
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "openid"
        ],
        redirect_uri=GOOGLE_REDIRECT_URI
    )
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
# Email reminders (upcoming bills)
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
        send_email(user.email, "Upcoming Bill Reminders - BillSmart", body)
        flash("Email reminders sent successfully! 📧", "success")
    except Exception as e:
        print("EMAIL ERROR:", e)
        flash("Error sending email reminders. Check email configuration.", "danger")

    return redirect(url_for("dashboard"))


# -------------------------------------------------
# WhatsApp reminders (upcoming bills)
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
        print("SENDING:", user.name, b.title, b.amount, b.due_date)   # <-- sample output / debugging

        url = f"https://graph.facebook.com/v18.0/{PHONE_NUMBER_ID}/messages"
        headers = {
            "Authorization": f"Bearer {WHATSAPP_TOKEN}",
            "Content-Type": "application/json"
        }

        data = {
            "messaging_product": "whatsapp",
            "to": USER_WHATSAPP_NUMBER,
            "type": "template",
            "template": {
                "name": "bill_reminder",                # <-- your template name
                "language": { "code": "en_US" },
                "components": [
                    {
                        "type": "body",
                        "parameters": [
                            {"type": "text", "text": user.name},           # {{1}}
                            {"type": "text", "text": b.title},             # {{2}}
                            {"type": "text", "text": str(b.amount)},       # {{3}}
                            {"type": "text", "text": str(b.due_date)}      # {{4}}
                        ]
                    }
                ]
            }
        }

        response = requests.post(url, json=data, headers=headers)
        print("\nWHATSAPP RESPONSE:", response.text, "\n")

    flash("WhatsApp bill reminders sent successfully! 📱", "success")
    return redirect(url_for("dashboard"))



# -------------------------------------------------
# Bill CRUD
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
from flask import make_response
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
    # Check state to avoid CSRF issues
    state = session.get("state")
    incoming_state = request.args.get("state")

    if not state or state != incoming_state:
        session.pop("state", None)
        return redirect(url_for("login_google"))

    flow = Flow.from_client_secrets_file(
        "client_secret_google.json",
        scopes=[
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "openid"
        ],
        state=state,
        redirect_uri=GOOGLE_REDIRECT_URI
    )
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    request_session = requests.Session()
    token_request = google.auth.transport.requests.Request(session=request_session)
    id_info = google.oauth2.id_token.verify_oauth2_token(
        credentials._id_token,
        token_request,
        GOOGLE_CLIENT_ID
    )

    google_email = id_info.get("email")
    google_name = id_info.get("name")

    # Check if user exists
    user = User.query.filter_by(email=google_email).first()

    if not user:
        # Auto-register Google user
        user = User(
            name=google_name,
            email=google_email,
            password=generate_password_hash("GOOGLE_AUTH")
        )
        db.session.add(user)
        db.session.commit()

    # Use your existing session-based login system
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
