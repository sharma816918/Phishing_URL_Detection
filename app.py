from flask import Flask, render_template, request, redirect, url_for, flash
import mysql.connector
import os
from urllib.parse import urlparse
import ipaddress


app = Flask(__name__)
app.secret_key = "phishing-url-detection-secret-key"


# =========================
# DATABASE CONNECTION
# =========================

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "phishing_detection"),
        ssl_disabled=False
    )


# =========================
# CREATE TABLE
# =========================

def init_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS urls (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url VARCHAR(2048) NOT NULL,
                status VARCHAR(50) NOT NULL,
                risk_score INT NOT NULL,
                reasons TEXT,
                checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        cursor.close()
        conn.close()

    except Exception as e:
        print("Database initialization error:", e)


# =========================
# URL ANALYSIS
# =========================

def analyze_url(url):

    score = 0
    reasons = []

    original_url = url.strip()

    # Add scheme for proper parsing
    parse_url = original_url

    if not parse_url.startswith(("http://", "https://")):
        parse_url = "http://" + parse_url

    try:
        parsed = urlparse(parse_url)
        hostname = parsed.hostname

        if not hostname:
            return {
                "status": "Invalid URL",
                "risk_score": 100,
                "reasons": ["Invalid hostname"]
            }

    except Exception:
        return {
            "status": "Invalid URL",
            "risk_score": 100,
            "reasons": ["Unable to parse URL"]
        }


    # =========================
    # URL LENGTH
    # =========================

    if len(original_url) > 100:
        score += 15
        reasons.append("Very long URL")

    elif len(original_url) > 75:
        score += 10
        reasons.append("Long URL")


    # =========================
    # HTTPS CHECK
    # =========================

    if parsed.scheme != "https":
        score += 10
        reasons.append("URL does not use HTTPS")


    # =========================
    # IP ADDRESS CHECK
    # =========================

    try:
        ipaddress.ip_address(hostname)
        score += 25
        reasons.append("URL uses an IP address instead of a domain name")

    except ValueError:
        pass


    # =========================
    # @ SYMBOL CHECK
    # =========================

    if "@" in original_url:
        score += 20
        reasons.append("URL contains @ symbol")


    # =========================
    # SUSPICIOUS KEYWORDS
    # =========================

    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "account",
        "password",
        "banking",
        "update",
        "confirm"
    ]

    found_keywords = []

    url_lower = original_url.lower()

    for keyword in suspicious_keywords:

        if keyword in url_lower and keyword not in found_keywords:
            found_keywords.append(keyword)

    if found_keywords:

        keyword_score = min(len(found_keywords) * 5, 20)

        score += keyword_score

        reasons.append(
            "Suspicious keywords found: "
            + ", ".join(found_keywords)
        )


    # =========================
    # HYPHEN CHECK
    # =========================

    if hostname.count("-") >= 3:
        score += 15
        reasons.append("Domain contains multiple hyphens")


    # =========================
    # SUBDOMAIN CHECK
    # =========================

    hostname_parts = hostname.split(".")

    if len(hostname_parts) >= 5:
        score += 15
        reasons.append("URL contains many subdomains")


    # =========================
    # URL SHORTENER CHECK
    # =========================

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "rb.gy"
    ]

    if hostname.lower() in shorteners:
        score += 20
        reasons.append("URL uses a URL shortening service")


    # =========================
    # LIMIT SCORE TO 100
    # =========================

    score = min(score, 100)


    # =========================
    # FINAL STATUS
    # =========================

    if score >= 50:

        status = "Potentially Phishing"

    elif score >= 25:

        status = "Suspicious"

    else:

        status = "Lower Risk"


    if not reasons:
        reasons.append("No major suspicious patterns detected")


    return {
        "status": status,
        "risk_score": score,
        "reasons": reasons
    }


# =========================
# HOME PAGE
# =========================

@app.route("/")
def index():

    total = 0
    lower_risk = 0
    suspicious = 0
    phishing = 0

    try:

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT COUNT(*) AS total FROM urls")
        total = cursor.fetchone()["total"]

        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM urls
            WHERE status = 'Lower Risk'
        """)

        lower_risk = cursor.fetchone()["count"]

        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM urls
            WHERE status = 'Suspicious'
        """)

        suspicious = cursor.fetchone()["count"]

        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM urls
            WHERE status = 'Potentially Phishing'
        """)

        phishing = cursor.fetchone()["count"]

        cursor.close()
        conn.close()

    except Exception as e:

        print("Dashboard database error:", e)


    return render_template(
        "index.html",
        total=total,
        lower_risk=lower_risk,
        suspicious=suspicious,
        phishing=phishing
    )


# =========================
# CHECK URL
# =========================

@app.route("/check", methods=["POST"])
def check_url():

    url = request.form.get("url", "").strip()


    # Empty URL check
    if not url:

        flash("Please enter a URL.", "error")

        return redirect(url_for("index"))


    # Analyze URL
    result = analyze_url(url)


    # Invalid URL
    if result["status"] == "Invalid URL":

        flash("Please enter a valid URL.", "error")

        return redirect(url_for("index"))


    # Convert reasons list into text
    reasons_text = ", ".join(result["reasons"])


    # Save result to database
    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO urls
            (url, status, risk_score, reasons)
            VALUES (%s, %s, %s, %s)
        """, (
            url,
            result["status"],
            result["risk_score"],
            reasons_text
        ))

        conn.commit()

        cursor.close()
        conn.close()

    except Exception as e:

        print("Database insert error:", e)

        flash(
            "URL analyzed, but database could not save the result.",
            "error"
        )

        return redirect(url_for("index"))


    # Show result on home page
    total = 0
    lower_risk = 0
    suspicious = 0
    phishing = 0

    try:

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT COUNT(*) AS total FROM urls")
        total = cursor.fetchone()["total"]

        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM urls
            WHERE status = 'Lower Risk'
        """)

        lower_risk = cursor.fetchone()["count"]

        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM urls
            WHERE status = 'Suspicious'
        """)

        suspicious = cursor.fetchone()["count"]

        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM urls
            WHERE status = 'Potentially Phishing'
        """)

        phishing = cursor.fetchone()["count"]

        cursor.close()
        conn.close()

    except Exception as e:

        print("Statistics error:", e)


    return render_template(
        "index.html",
        result=result,
        checked_url=url,
        total=total,
        lower_risk=lower_risk,
        suspicious=suspicious,
        phishing=phishing
    )


# =========================
# HISTORY PAGE
# =========================

@app.route("/history")
def history():

    records = []

    try:

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT *
            FROM urls
            ORDER BY checked_at DESC
        """)

        records = cursor.fetchall()

        cursor.close()
        conn.close()

    except Exception as e:

        print("History database error:", e)


    return render_template(
        "history.html",
        records=records
    )


# =========================
# CLEAR HISTORY
# =========================

@app.route("/clear-history", methods=["POST"])
def clear_history():

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM urls")

        conn.commit()

        cursor.close()
        conn.close()

        flash("History cleared successfully.", "success")

    except Exception as e:

        print("Clear history error:", e)

        flash(
            "Unable to clear history.",
            "error"
        )


    return redirect(url_for("history"))


# =========================
# START APPLICATION
# =========================

if __name__ == "__main__":

    init_db()

    app.run(
        debug=True,
        host="0.0.0.0"
    )