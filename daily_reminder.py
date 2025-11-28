#!/usr/bin/env python3
"""
daily_reminder.py

Usage:
  python daily_reminder.py               # default: send reminders for bills due in 1 day
  python daily_reminder.py --days 2      # send for bills due in 2 days
  python daily_reminder.py --dry-run     # don't actually send, just print what would be sent
"""

import argparse
import logging
import os
from collections import defaultdict
from datetime import datetime, date, timedelta, time

# timezone support
try:
    from zoneinfo import ZoneInfo
except Exception:
    # fallback for older Python with pytz installed
    from pytz import timezone as _pytz_timezone

    def ZoneInfo(name):
        return _pytz_timezone(name)

# DB / app imports — app.py must expose: app, db, User, Bill, send_whatsapp_message, send_email_raw (or send_email)
from app import app, db, User, Bill

# Try to import send_whatsapp_message & send_email_raw / send_email
try:
    from app import send_whatsapp_message
except Exception:
    send_whatsapp_message = None

send_email = None
try:
    # prefer send_email_raw (or any send_email function your app exposes)
    from app import send_email_raw as send_email
except Exception:
    try:
        from app import send_email as send_email
    except Exception:
        send_email = None

# logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("daily_reminder")


def get_timezone():
    tz_name = os.getenv("TIMEZONE", "Asia/Kolkata")
    try:
        return ZoneInfo(tz_name)
    except Exception:
        logger.warning("Invalid TIMEZONE '%s', falling back to UTC", tz_name)
        try:
            return ZoneInfo("UTC")
        except Exception:
            return None


def normalize_phone(phone: str) -> str | None:
    if not phone:
        return None
    s = "".join(ch for ch in phone if ch.isdigit())
    if len(s) == 10:  # assume Indian number if 10 digits
        return "91" + s
    if len(s) > 10 and s.startswith("0"):
        # strip leading 0 then prefix country? keep it simple: remove leading zero
        return s.lstrip("0")
    return s  # assume already international


def email_credentials_present() -> bool:
    addr = os.getenv("EMAIL_ADDRESS")
    pwd = os.getenv("EMAIL_PASSWORD")
    return bool(addr and pwd)


def query_bills_for_date(target_date):
    """Return list of Bill objects due on the given date (date object)."""
    with app.app_context():
        try:
            # If due_date is a DATE column:
            return Bill.query.filter(func_date(Bill.due_date) == target_date).all()
        except Exception:
            # fallback: compare date portion using range
            start = datetime.combine(target_date, time.min)
            end = datetime.combine(target_date, time.max)
            return Bill.query.filter(Bill.due_date >= start, Bill.due_date <= end).all()


# helper to avoid direct SA `func.date` dependency in multiple environments
def func_date(col):
    # import here to avoid errors when module loaded without SQLAlchemy available
    from sqlalchemy import func
    return func.date(col)


def build_messages_per_user(bills):
    """
    Group bills by user and prepare messages.
    Returns dict: user -> list[bills]
    """
    users_map = defaultdict(list)
    with app.app_context():
        for bill in bills:
            user = db.session.get(User, bill.user_id)
            if user:
                users_map[user].append(bill)
    return users_map


def format_email(user, bills, days_ahead: int):
    lines = [
        f"Hi {user.name},",
        "",
        f"You have {len(bills)} bill(s) due in {days_ahead} day(s):",
        ""
    ]
    for b in bills:
        lines.append(f"- {b.title} | ₹{b.amount} | Due: {b.due_date}")
    lines.append("")
    lines.append("Regards,\nBillSmart Team")
    return "\n".join(lines)


def format_whatsapp(user, bills, days_ahead: int):
    lines = [f"⏰ BillSmart Reminder — due in {days_ahead} day(s):"]
    for b in bills:
        lines.append(f"{b.title} — ₹{b.amount} — Due: {b.due_date}")
    lines.append("")
    lines.append("Reply STOP to opt-out.")  # optional guidance
    return "\n".join(lines)


def send_reminders_for_days(days_ahead: int = 1, dry_run: bool = False):
    tz = get_timezone()
    now = datetime.now(tz) if tz else datetime.utcnow()
    target = (now + timedelta(days=days_ahead)).date()
    logger.info("Looking for bills due on %s (days_ahead=%d tz=%s)", target, days_ahead, os.getenv("TIMEZONE", "Asia/Kolkata"))

    # gather bills
    with app.app_context():
        try:
            # prefer SQL-level date filter if possible
            bills = Bill.query.filter(func_date(Bill.due_date) == target).all()
        except Exception:
            start = datetime.combine(target, time.min)
            end = datetime.combine(target, time.max)
            bills = Bill.query.filter(Bill.due_date >= start, Bill.due_date <= end).all()

    logger.info("Found %d bill(s) due on %s", len(bills), target)
    if not bills:
        return 0

    users_map = build_messages_per_user(bills)
    total_wa = 0
    total_email = 0

    for user, user_bills in users_map.items():
        # Email
        if send_email and user.email and email_credentials_present():
            subject = f"BillSmart: {len(user_bills)} bill(s) due in {days_ahead} day(s)"
            body = format_email(user, user_bills, days_ahead)
            if dry_run:
                logger.info("[DRY-RUN] EMAIL to %s: %s", user.email, body)
            else:
                try:
                    ok = send_email(user.email, subject, body)
                    total_email += 1 if ok is not False else 0
                    logger.info("Sent Email to %s (ok=%s)", user.email, ok)
                except Exception as e:
                    logger.exception("Failed to send email to %s: %s", user.email, e)
        else:
            logger.debug("Skipping email for user %s (send_email=%s, email=%s, creds=%s)", getattr(user, "id", None), bool(send_email), user.email, email_credentials_present())

        # WhatsApp
        if send_whatsapp_message and getattr(user, "phone", None):
            phone = normalize_phone(user.phone)
            wa_msg = format_whatsapp(user, user_bills, days_ahead)
            if dry_run:
                logger.info("[DRY-RUN] WHATSAPP to %s: %s", phone, wa_msg)
            else:
                try:
                    ok = send_whatsapp_message(phone, wa_msg)
                    if ok:
                        total_wa += 1
                    logger.info("WhatsApp send to %s ok=%s", phone, ok)
                except Exception as e:
                    logger.exception("Failed to send WhatsApp to %s: %s", phone, e)
        else:
            logger.debug("Skipping WhatsApp for user %s (has_phone=%s send_whatsapp=%s)", getattr(user, "id", None), bool(getattr(user, "phone", None)), bool(send_whatsapp_message))

    logger.info("Done. WhatsApp attempts: %d, Emails attempted: %d", total_wa, total_email)
    return total_wa


def main():
    parser = argparse.ArgumentParser(description="Daily reminders for BillSmart")
    parser.add_argument("--days", type=int, default=1, help="Days ahead to check (default 1)")
    parser.add_argument("--dry-run", action="store_true", help="Do not actually send; just log")
    args = parser.parse_args()

    logger.info("Starting daily_reminder (days=%s dry_run=%s)", args.days, args.dry_run)
    send_reminders_for_days(args.days, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
