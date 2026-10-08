from flask import Flask, render_template, request, redirect, url_for, flash
import mysql.connector
import os
import re
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "phishing-url-detection-secret")


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "phishing_detection"),
        ssl_disabled=False
    )


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def init_db():
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

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

        connection.commit()

        print("Database initialized successfully.")

    except Exception as e:
        print("Database initialization error:", e)

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_url(url):

    risk = 0
    reasons = []

    # -----------------------------------------------------
    # Add scheme if missing
    # -----------------------------------------------------

    original_url = url.strip()

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", original_url):
        parsed_url = urlparse("http://" + original_url)
    else:
        parsed_url = urlparse(original_url)

    hostname = parsed_url.hostname

    # -----------------------------------------------------
    # Invalid hostname
    # -----------------------------------------------------

    if not hostname:
        return {
            "status": "Invalid URL",
            "risk": 100,
            "reasons": ["Unable to identify a valid hostname."]
        }

    hostname = hostname.lower()

    # -----------------------------------------------------
    # URL Length
    # -----------------------------------------------------

    if len(original_url) > 100:
        risk += 15
        reasons.append("URL is unusually long.")

    elif len(original_url) > 75:
        risk += 10
        reasons.append("URL is relatively long.")

    # -----------------------------------------------------
    # HTTPS Check
    # -----------------------------------------------------

    if parsed_url.scheme.lower() != "https":
        risk += 10
        reasons.append("URL does not use HTTPS.")

    # -----------------------------------------------------
    # IP Address Check
    # -----------------------------------------------------

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, hostname):
        risk += 25
        reasons.append("URL uses an IP address instead of a domain name.")

    # -----------------------------------------------------
    # @ Symbol
    # -----------------------------------------------------

    if "@" in original_url:
        risk += 20
        reasons.append("URL contains '@' symbol, which can hide the actual destination.")

    # -----------------------------------------------------
    # Suspicious Keywords
    # -----------------------------------------------------

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
        if keyword in url_lower:
            found_keywords.append(keyword)

    if found_keywords:
        keyword_score = min(len(found_keywords) * 5, 20)
        risk += keyword_score

        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(found_keywords)
            + "."
        )

    # -----------------------------------------------------
    # Multiple Hyphens in Domain
    # -----------------------------------------------------

    if hostname.count("-") >= 3:
        risk += 15
        reasons.append("Domain contains multiple hyphens.")

    # -----------------------------------------------------
    # Too Many Subdomains
    # -----------------------------------------------------

    hostname_parts = hostname.split(".")

    if len(hostname_parts) >= 5:
        risk += 15
        reasons.append("Domain contains many subdomain components.")

    # -----------------------------------------------------
    # URL Shorteners
    # -----------------------------------------------------

    shortener_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "rb.gy"
    ]

    if hostname in shortener_domains:
        risk += 20
        reasons.append("URL uses a known URL shortening service.")

    # -----------------------------------------------------
    # Limit Risk Score
    # -----------------------------------------------------

    risk = min(risk, 100)

    # -----------------------------------------------------
    # Determine Status
    # -----------------------------------------------------

    if risk >= 50:
        status = "Potentially Phishing"

    elif risk >= 25:
        status = "Suspicious"

    else:
        status = "Lower Risk"

    # -----------------------------------------------------
    # No reasons
    # -----------------------------------------------------

    if not reasons:
        reasons.append("No major suspicious characteristics detected.")

    return {
        "status": status,
        "risk": risk,
        "reasons": reasons
    }


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/")
def index():

    stats = {
        "total": 0,
        "safe": 0,
        "suspicious": 0,
        "phishing": 0
    }

    recent_urls = []

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Total URLs
        cursor.execute("SELECT COUNT(*) AS total FROM urls")
        result = cursor.fetchone()

        if result:
            stats["total"] = result["total"]

        # Lower Risk
        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM urls
            WHERE status = 'Lower Risk'
        """)

        result = cursor.fetchone()

        if result:
            stats["safe"] = result["total"]

        # Suspicious
        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM urls
            WHERE status = 'Suspicious'
        """)

        result = cursor.fetchone()

        if result:
            stats["suspicious"] = result["total"]

        # Potentially Phishing
        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM urls
            WHERE status = 'Potentially Phishing'
        """)

        result = cursor.fetchone()

        if result:
            stats["phishing"] = result["total"]

        # Recent URLs
        cursor.execute("""
            SELECT *
            FROM urls
            ORDER BY id DESC
            LIMIT 5
        """)

        recent_urls = cursor.fetchall()

    except Exception as e:

        print("Dashboard database error:", e)

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()

    return render_template(
        "index.html",
        stats=stats,
        recent_urls=recent_urls,
        result=None,
        url="",
        status=None,
        risk_score=None,
        reasons=[],
        safe=stats["safe"],
        suspicious=stats["suspicious"],
        phishing=stats["phishing"]
    )


# =========================================================
# CHECK URL
# =========================================================

@app.route("/check", methods=["POST"])
def check_url():

    url = request.form.get("url", "").strip()

    if not url:
        flash("Please enter a URL.", "error")
        return redirect(url_for("index"))

    # Analyze URL
    analysis = analyze_url(url)

    status = analysis["status"]
    risk_score = analysis["risk"]
    reasons = analysis["reasons"]

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        reasons_text = "\n".join(reasons)

        cursor.execute("""
            INSERT INTO urls
            (url, status, risk_score, reasons)
            VALUES (%s, %s, %s, %s)
        """, (
            url,
            status,
            risk_score,
            reasons_text
        ))

        connection.commit()

    except Exception as e:

        print("Database insert error:", e)
        flash("URL analyzed, but database saving failed.", "error")

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()

    # Get updated dashboard statistics
    stats = {
        "total": 0,
        "safe": 0,
        "suspicious": 0,
        "phishing": 0
    }

    recent_urls = []

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT COUNT(*) AS total FROM urls")
        stats["total"] = cursor.fetchone()["total"]

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM urls
            WHERE status = 'Lower Risk'
        """)
        stats["safe"] = cursor.fetchone()["total"]

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM urls
            WHERE status = 'Suspicious'
        """)
        stats["suspicious"] = cursor.fetchone()["total"]

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM urls
            WHERE status = 'Potentially Phishing'
        """)
        stats["phishing"] = cursor.fetchone()["total"]

        cursor.execute("""
            SELECT *
            FROM urls
            ORDER BY id DESC
            LIMIT 5
        """)

        recent_urls = cursor.fetchall()

    except Exception as e:

        print("Statistics database error:", e)

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()

    return render_template(
        "index.html",
        stats=stats,
        recent_urls=recent_urls,
        result=analysis,
        url=url,
        status=status,
        risk_score=risk_score,
        reasons=reasons,
        safe=stats["safe"],
        suspicious=stats["suspicious"],
        phishing=stats["phishing"]
    )


# =========================================================
# HISTORY
# =========================================================

@app.route("/history")
def history():

    records = []

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT *
            FROM urls
            ORDER BY id DESC
        """)

        records = cursor.fetchall()

    except Exception as e:

        print("History database error:", e)

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()

    return render_template(
        "history.html",
        records=records
    )


# =========================================================
# CLEAR HISTORY
# =========================================================

@app.route("/clear-history", methods=["POST"])
def clear_history():

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("DELETE FROM urls")

        connection.commit()

        flash("History cleared successfully.", "success")

    except Exception as e:

        print("Clear history error:", e)
        flash("Unable to clear history.", "error")

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()

    return redirect(url_for("history"))


# =========================================================
# INITIALIZE DATABASE
# =========================================================

# Important for Render + Gunicorn
try:
    init_db()
except Exception as e:
    print("Startup database error:", e)


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000))
    )