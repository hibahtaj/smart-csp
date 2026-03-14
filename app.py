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

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

from utils.scoring import compute_strength_score, compute_baseline_score, compute_readability_score, generate_advanced_resource_analysis, generate_block_summary, generate_csp_explanations
from utils.charts import (
    generate_strength_donut,
    generate_strength_comparison,
    generate_resource_breakdown,
    generate_test_results,
    generate_security_radar
)
import uuid
import json

app = Flask(__name__)

SCAN_DIR = "scans"
os.makedirs(SCAN_DIR, exist_ok=True)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('website_url')
        driver = None
        try:
            # Selenium headless browser setup
            options = Options()
            options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.page_load_strategy = "eager"

            prefs = {
                "profile.managed_default_content_settings.images": 2
            }
            options.add_experimental_option("prefs", prefs)

            driver = webdriver.Chrome(options=options)

            driver.set_page_load_timeout(15)

            driver = webdriver.Chrome(options=options)

            driver.get(url)

            # Scripts
            scripts = []

            for s in driver.find_elements("tag name", "script"):
                try:
                    src = s.get_attribute("src")
                    if src:
                        scripts.append(urljoin(driver.current_url, src))
                except:
                    pass

            # Images
            images = []

            for i in driver.find_elements("tag name", "img"):
                try:
                    src = i.get_attribute("src")
                    if src:
                        images.append(urljoin(driver.current_url, src))
                except:
                    pass

            # CSS files
            css_files = []

            for c in driver.find_elements("tag name", "link"):
                try:
                    rel = c.get_attribute("rel")
                    href = c.get_attribute("href")
                    if rel == "stylesheet" and href:
                        css_files.append(urljoin(driver.current_url, href))
                except:
                    pass

            # Fonts
            fonts = []

            for f in driver.find_elements("tag name", "link"):
                try:
                    href = f.get_attribute("href")
                    if href and "font" in href:
                        fonts.append(urljoin(driver.current_url, href))
                except:
                    pass

            # Objects 
            objects = []
            for o in driver.find_elements("tag name", "object"):
                try:
                    obj = o.get_attribute("data")
                    if obj:
                        objects.append(urljoin(driver.current_url, obj))
                except:
                    pass

            # Generate clean CSP header
            csp_rule = generate_csp(scripts, images, css_files, fonts)

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



            BASE_DIR = os.path.abspath(os.getcwd())
            CHART_DIR = os.path.join(BASE_DIR, "static", "charts")

            # ---- STORE DATA FOR REPORT ----

            scan_id = str(uuid.uuid4().hex[:8])

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
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M")
            }

            scan_path = os.path.join(SCAN_DIR, f"{scan_id}.json")

            with open(scan_path, "w") as f:
                json.dump(scan_data, f)

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

    scan_path = os.path.join(SCAN_DIR, f"{scan_id}.json")

    if not os.path.exists(scan_path):
        return redirect(url_for("index"))

    with open(scan_path) as f:
        scan = json.load(f)

    return render_template("results.html", **scan, scan_id=scan_id)

@app.route("/report/preview/<scan_id>")
def report_preview(scan_id):

    scan_path = os.path.join(SCAN_DIR, f"{scan_id}.json")

    if not os.path.exists(scan_path):
        return redirect(url_for("index"))

    with open(scan_path) as f:
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