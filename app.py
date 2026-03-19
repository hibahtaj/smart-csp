from flask import Flask, redirect, render_template, request, send_file, url_for
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from urllib.parse import urljoin
from csp_generator.generate_csp import generate_csp
from sandbox.test_csp import test_csp
from datetime import datetime
import os
import traceback
from weasyprint import HTML
import base64
from email_validator import validate_email, EmailNotValidError

from urllib.parse import urljoin

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

from utils.scoring import compute_strength_score, compute_baseline_score, compute_readability_score, generate_advanced_resource_analysis, generate_block_summary, generate_csp_explanations, check_owasp_compliance, check_google_csp, check_w3c_compliance
from utils.charts import (
    generate_strength_donut,
    generate_strength_comparison,
    generate_resource_breakdown,
    generate_test_results,
    generate_security_radar
)
import uuid
import json
import hashlib
import time

app = Flask(__name__)

SCAN_DIR = "scans"
CACHE_DIR = os.path.join(SCAN_DIR, "cache")

os.makedirs(SCAN_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

def get_cache_filename(url):
    return os.path.join(
        CACHE_DIR, 
        hashlib.md5(url.encode()).hexdigest() + ".json"
        )

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('website_url')
        url = url.strip().lower().rstrip("/")

        cache_file = get_cache_filename(url)

        if os.path.exists(cache_file):
            print("CACHE HIT")
            with open(cache_file, "r") as f:
                cached_data = json.load(f)
            scan_id = uuid.uuid4().hex[:8]
            scan_path = os.path.join(SCAN_DIR, f"{scan_id}.json")
            
            with open(scan_path, "w") as f:
                json.dump(cached_data, f, indent=2)

            time.sleep(15)
            
            return redirect(url_for("results", scan_id=scan_id))
        
        driver = None
        try:
            # Selenium headless browser setup

            options = Options()

            options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")

            # performance flags
            options.add_argument("--disable-extensions")
            options.add_argument("--disable-infobars")
            options.add_argument("--disable-notifications")
            options.add_argument("--disable-popup-blocking")
            options.add_argument("--disable-background-networking")
            options.add_argument("--disable-sync")
            options.add_argument("--metrics-recording-only")
            options.add_argument("--no-first-run")

            options.page_load_strategy = "eager"

            # disable images (IMPORTANT)
            prefs = {
                "profile.managed_default_content_settings.images": 2
            }
            options.add_experimental_option("prefs", prefs)


            driver = webdriver.Chrome(options=options)

            driver.set_page_load_timeout(20)

            driver.get(url)

            driver.implicitly_wait(2)

            resources = driver.execute_script("""
            let getAbsolute = (url) => {
                try { return new URL(url, document.baseURI).href; }
                catch { return null; }
            };

            return {
                scripts: Array.from(document.querySelectorAll('script[src]'))
                    .map(s => getAbsolute(s.src)).filter(Boolean),

                images: Array.from(document.querySelectorAll('img[src]'))
                    .map(i => getAbsolute(i.src)).filter(Boolean),

                css: Array.from(document.querySelectorAll('link[rel="stylesheet"][href]'))
                    .map(l => getAbsolute(l.href)).filter(Boolean),

                fonts: Array.from(document.querySelectorAll('link[href]'))
                    .map(l => l.href)
                    .filter(h => h && h.toLowerCase().includes("font"))
                    .map(h => getAbsolute(h)).filter(Boolean),

                objects: Array.from(document.querySelectorAll('object[data]'))
                    .map(o => getAbsolute(o.data)).filter(Boolean)
            };
            """)

            scripts = resources["scripts"]
            images = resources["images"]
            css_files = resources["css"]
            fonts = resources["fonts"]
            objects = resources["objects"]

            # Generate clean CSP header
            csp_rule = generate_csp(scripts, images, css_files, fonts, objects)

            # ---- AFTER sandbox test ----
            blocked_resources = test_csp(driver, url, csp_rule)

            # ---- METRICS ----
            smart_score = compute_strength_score(csp_rule)
            baseline_score = compute_baseline_score(None)
            readability_score = compute_readability_score(csp_rule)
            block_summary = generate_block_summary(csp_rule)
            resource_analysis = generate_advanced_resource_analysis(
    scripts, images, css_files, fonts, blocked_resources
)
            csp_explanations = generate_csp_explanations(csp_rule)

            owasp_verified = check_owasp_compliance(csp_rule)
            w3c_verified = check_w3c_compliance(csp_rule)
            google_verified = check_google_csp(csp_rule)

            # ---- STORE DATA FOR REPORT ----

            scan_data = {
                "url": url,
                "scripts": scripts,
                "images": images,
                "css_files": css_files,
                "fonts": fonts,
                "csp_rule": csp_rule,
                "resource_analysis": resource_analysis,
                "blocked_resources": blocked_resources,
                "strength_score": smart_score,
                "baseline_score": baseline_score,
                "csp_explanations": csp_explanations,
                "readability_score": readability_score,
                "block_summary": block_summary,
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "owasp_verified": owasp_verified,
                "w3c_verified": w3c_verified,
                "google_verified": google_verified
            }

            with open(cache_file, "w") as f:
                json.dump(scan_data, f, indent=2)
            
            scan_id = uuid.uuid4().hex[:8]
            scan_path = os.path.join(SCAN_DIR, f"{scan_id}.json")

            with open(scan_path, "w") as f:
                json.dump(scan_data, f, indent=2)
            
            return redirect(url_for("results", scan_id=scan_id))

        except Exception as e:
            traceback.print_exc()
            return f"Error fetching website: {str(e)}"
        
        finally:
            if driver:
                driver.quit()

    return render_template('index.html')

@app.route("/results/<scan_id>")
def results(scan_id):

    path = os.path.join(SCAN_DIR, f"{scan_id}.json")

    if not os.path.exists(path):
        return redirect(url_for("index"))

    with open(path) as f:
        data = json.load(f)

    return render_template("results.html", data=data, scan_id=scan_id)

@app.route("/report/preview/<scan_id>")
def report_preview(scan_id):

    path = os.path.join(SCAN_DIR, f"{scan_id}.json")

    if not os.path.exists(path):
        return redirect(url_for("index"))

    with open(path) as f:
        scan = json.load(f)
    
    PDF_PATH = os.path.join(SCAN_DIR, f"{scan_id}.pdf")
    BASE_DIR = os.path.abspath(os.getcwd())
    CHART_DIR = os.path.join(BASE_DIR, "static", "charts")

    generate_strength_donut(scan["strength_score"], CHART_DIR)
    generate_resource_breakdown(
        scan["scripts"],
        scan["images"],
        scan["css_files"],
        scan["fonts"],
        CHART_DIR
    )
    generate_test_results(
        len(scan["scripts"]) +
        len(scan["images"]) +
        len(scan["css_files"]) +
        len(scan["fonts"]),
        len(scan["blocked_resources"]),
        CHART_DIR
    )
    generate_security_radar(scan["csp_rule"], CHART_DIR)


    html_content = render_template(
        "report.html",
        base_path=BASE_DIR,

        url=scan["url"],
        scan_date=scan["scan_date"],
        csp_rule=scan["csp_rule"],

        scripts=scan["scripts"],
        images=scan["images"],
        css_files=scan["css_files"],
        fonts=scan["fonts"],
        blocked_resources=scan["blocked_resources"],

        strength_score=scan["strength_score"],
        baseline_score=scan["baseline_score"],
        readability_score=scan["readability_score"],

        csp_explanations=scan["csp_explanations"],
        resource_analysis=scan["resource_analysis"]
    )

    HTML(string=html_content, base_url=BASE_DIR).write_pdf(PDF_PATH)

    return send_file(PDF_PATH, mimetype="application/pdf")

@app.route("/send-report-email/<scan_id>", methods=["POST"])
def send_report_email(scan_id):
    scan_path = os.path.join(SCAN_DIR, f"{scan_id}.json")

    if not os.path.exists(scan_path):
        return {"status": "error", "message": "Scan not found"}, 404

    with open(scan_path) as f:
        scan = json.load(f)

    name = request.form.get("name")
    email = request.form.get("email")

    # ---- EMAIL VALIDATION ----
    if not name:
        return {"status": "error", "message": "Name is required"}, 400

    try:
        validated = validate_email(email)
        email = validated.email

    except EmailNotValidError as e:
        return {"status": "error", "message": str(e)}, 400

    try:

        BASE_DIR = os.path.abspath(os.getcwd())
        PDF_PATH = os.path.join(BASE_DIR, "static", "smartcsp_report.pdf")

        # ---- GENERATE REPORT IF NOT PRESENT ----
        if not os.path.exists(PDF_PATH):

            html_content = render_template(
                "report.html",
                base_path=BASE_DIR,
                **scan
            )

            HTML(string=html_content, base_url=BASE_DIR).write_pdf(PDF_PATH)

        # ---- SMTP CONFIG ----
        sender = os.environ.get("SMARTCSP_EMAIL_ID")
        password = os.environ.get("SMARTCSP_APP_PASSWORD")

        msg = MIMEMultipart("mixed")

        msg["From"] = f"SmartCSP Security <{sender}>"
        msg["To"] = email
        msg["Subject"] = "SmartCSP Security Report for " + scan["url"]

        # ---- HTML EMAIL TEMPLATE ----
        email_html = render_template(
            "email_template.html",
            name=name,
            website=scan["url"],
            scan_time=scan["scan_date"],
            csp_rule=scan["csp_rule"]
        )

        msg.attach(MIMEText(email_html, "html"))

        # ---- ATTACH PDF ----
        with open(PDF_PATH, "rb") as f:

            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())

        encoders.encode_base64(part)

        part.add_header(
            "Content-Disposition",
            "attachment; filename=SmartCSP_Report.pdf"
        )

        msg.attach(part)

        # ---- SEND EMAIL ----
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:

            server.login(sender, password)
            server.send_message(msg)

        return {"status": "success"}

    except Exception as e:
        return {"status": "error", "message": str(e)}, 500


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)