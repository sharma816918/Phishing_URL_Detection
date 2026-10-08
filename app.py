from flask import Flask, render_template, request, redirect
import mysql.connector
from urllib.parse import urlparse
import ipaddress

app = Flask(__name__)


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="phishing_detection"
    )


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_url(url):

    url = url.strip()

    check_url = url if "://" in url else "http://" + url

    parsed = urlparse(check_url)
    host = parsed.hostname or ""

    score = 0
    reasons = []

    if not host or "." not in host:
        return {
            "status": "Invalid URL",
            "risk": 0,
            "reasons": ["Please enter a valid website URL."]
        }

    # URL Length
    if len(url) > 100:
        score += 15
        reasons.append("Unusually long URL")

    elif len(url) > 75:
        score += 10
        reasons.append("Long URL")

    # HTTPS
    if parsed.scheme.lower() != "https":
        score += 10
        reasons.append("HTTPS is not used")

    # IP Address
    try:
        ipaddress.ip_address(host)

        score += 25
        reasons.append("IP address used as hostname")

    except ValueError:
        pass

    # @ Symbol
    if "@" in url:
        score += 20
        reasons.append("@ symbol found in URL")

    # Suspicious Keywords
    keywords = [
        "login",
        "verify",
        "secure",
        "account",
        "password",
        "banking",
        "update",
        "confirm"
    ]

    found_keywords = [
        word for word in keywords
        if word in url.lower()
    ]

    if found_keywords:

        score += min(20, len(found_keywords) * 5)

        reasons.append(
            "Potentially suspicious keywords: "
            + ", ".join(found_keywords)
        )

    # Hyphens
    if host.count("-") >= 3:

        score += 15

        reasons.append(
            "Many hyphens in hostname"
        )

    # Subdomains
    if len(host.split(".")) >= 5:

        score += 15

        reasons.append(
            "Many hostname components"
        )

    # URL Shorteners
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "rb.gy"
    ]

    if host.lower() in shorteners:

        score += 20

        reasons.append(
            "URL shortening service detected"
        )

    # Risk Score
    risk = min(score, 100)

    # Status
    if risk >= 50:
        status = "Potentially Phishing"

    elif risk >= 25:
        status = "Suspicious"

    else:
        status = "Lower Risk"

    if not reasons:
        reasons.append(
            "No listed warning signs detected"
        )

    return {
        "status": status,
        "risk": risk,
        "reasons": reasons
    }


# =========================================================
# DASHBOARD STATISTICS
# =========================================================

def get_statistics():

    connection = get_db_connection()
    cursor = connection.cursor()

    # Total
    cursor.execute(
        "SELECT COUNT(*) FROM urls"
    )

    total = cursor.fetchone()[0]

    # Safe
    cursor.execute(
        "SELECT COUNT(*) FROM urls "
        "WHERE status = 'Lower Risk'"
    )

    safe = cursor.fetchone()[0]

    # Suspicious
    cursor.execute(
        "SELECT COUNT(*) FROM urls "
        "WHERE status = 'Suspicious'"
    )

    suspicious = cursor.fetchone()[0]

    # Phishing
    cursor.execute(
        "SELECT COUNT(*) FROM urls "
        "WHERE status = 'Potentially Phishing'"
    )

    phishing = cursor.fetchone()[0]

    cursor.close()
    connection.close()

    return {
        "total": total,
        "safe": safe,
        "suspicious": suspicious,
        "phishing": phishing
    }


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():

    try:

        stats = get_statistics()

    except mysql.connector.Error as error:

        print("Database Error:", error)

        stats = {
            "total": 0,
            "safe": 0,
            "suspicious": 0,
            "phishing": 0
        }

    return render_template(
        "index.html",
        stats=stats
    )


# =========================================================
# CHECK URL
# =========================================================

@app.route("/check", methods=["POST"])
def check_url():

    url = request.form.get(
        "url",
        ""
    ).strip()

    if not url:

        return render_template(
            "index.html",
            error="Please enter a URL.",
            stats=get_statistics()
        )

    if len(url) > 2048:

        return render_template(
            "index.html",
            error="URL is too long.",
            stats=get_statistics()
        )

    # Analyze
    result = analyze_url(url)

    # Save to MySQL
    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        reasons_text = ", ".join(
            result["reasons"]
        )

        query = """
            INSERT INTO urls
            (url, status, risk_score, reasons)
            VALUES (%s, %s, %s, %s)
        """

        values = (
            url,
            result["status"],
            result["risk"],
            reasons_text
        )

        cursor.execute(
            query,
            values
        )

        connection.commit()

        cursor.close()
        connection.close()

    except mysql.connector.Error as error:

        print(
            "Database Error:",
            error
        )

    stats = get_statistics()

    return render_template(
        "index.html",
        checked_url=url,
        result=result,
        stats=stats
    )


# =========================================================
# HISTORY
# =========================================================

@app.route("/history")
def history():

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        query = """
            SELECT
                id,
                url,
                status,
                risk_score,
                checked_at
            FROM urls
            ORDER BY checked_at DESC
        """

        cursor.execute(query)

        records = cursor.fetchall()

        cursor.close()
        connection.close()

    except mysql.connector.Error as error:

        print(
            "Database Error:",
            error
        )

        records = []

    return render_template(
        "history.html",
        records=records
    )


# =========================================================
# CLEAR HISTORY
# =========================================================

@app.route("/clear-history", methods=["POST"])
def clear_history():

    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "DELETE FROM urls"
        )

        connection.commit()

        cursor.close()
        connection.close()

        print("History cleared successfully.")

    except mysql.connector.Error as error:

        print(
            "Database Error:",
            error
        )

    return redirect("/history")


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )