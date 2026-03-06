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
from weasyprint import HTML
import re
import base64
from email_validator import validate_email, EmailNotValidError

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import (
    Mail,
    Attachment,
    FileContent,
    FileName,
    FileType,
    Disposition
)

from utils.scoring import compute_strength_score, compute_baseline_score, compute_readability_score, generate_advanced_resource_analysis, generate_block_summary, generate_csp_explanations
from utils.charts import (
    generate_strength_donut,
    generate_strength_comparison,
    generate_resource_breakdown,
    generate_test_results,
    generate_security_radar
)

app = Flask(__name__)

# TEMPORARY in-memory storage (OK for now)
LATEST_SCAN = {}

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('website_url')

        try:
            # Selenium headless browser setup
            options = Options()
            options.add_argument("--headless")
            options.add_argument("--disable-gpu")
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)
            driver.get(url)

            # Scripts
            scripts = [urljoin(driver.current_url, s.get_attribute('src'))
                       for s in driver.find_elements("tag name", "script")
                       if s.get_attribute('src')]

            # Images
            images = [urljoin(driver.current_url, i.get_attribute('src'))
                      for i in driver.find_elements("tag name", "img")
                      if i.get_attribute('src')]

            # CSS files
            css_files = [urljoin(driver.current_url, c.get_attribute('href'))
                         for c in driver.find_elements("tag name", "link")
                         if c.get_attribute('rel') == 'stylesheet' and c.get_attribute('href')]

            # Fonts
            fonts = [urljoin(driver.current_url, f.get_attribute('href'))
                     for f in driver.find_elements("tag name", "link")
                     if f.get_attribute('href') and 'font' in f.get_attribute('href')]

            # Objects 
            objects = [urljoin(driver.current_url, o.get_attribute('data'))
                    for o in driver.find_elements("tag name", "object")
                    if o.get_attribute('data')]


            driver.quit()

            # Generate clean CSP header
            csp_rule = generate_csp(scripts, images, css_files, fonts)

            # ---- AFTER sandbox test ----
            blocked_resources = test_csp(url, csp_rule)

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
            LATEST_SCAN.clear()
            LATEST_SCAN.update({
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
            })


            return redirect(url_for("results"))

        except Exception as e:
            return f"Error fetching website: {e}"

    return render_template('index.html')

@app.route("/results")
def results():
    if not LATEST_SCAN:
        return redirect(url_for("index"))

    return render_template(
        "results.html",
        url=LATEST_SCAN["url"],
        csp_rule=LATEST_SCAN["csp_rule"],
        strength_score=LATEST_SCAN["strength_score"],
        readability_score=LATEST_SCAN["readability_score"],
        block_summary=LATEST_SCAN["block_summary"],
        csp_explanations=LATEST_SCAN["csp_explanations"],
        resource_analysis=LATEST_SCAN["resource_analysis"]
    )

@app.route("/report/preview")
def report_preview():
    if not LATEST_SCAN:
        return redirect(url_for("index"))

    BASE_DIR = os.path.abspath(os.getcwd())
    CHART_DIR = os.path.join(BASE_DIR, "static", "charts")
    PDF_PATH = os.path.join(BASE_DIR, "static", "smartcsp_preview.pdf")

    generate_strength_donut(LATEST_SCAN["strength_score"], CHART_DIR)
    generate_resource_breakdown(
        LATEST_SCAN["scripts"],
        LATEST_SCAN["images"],
        LATEST_SCAN["css_files"],
        LATEST_SCAN["fonts"],
        CHART_DIR
    )
    generate_test_results(
        len(LATEST_SCAN["scripts"]) +
        len(LATEST_SCAN["images"]) +
        len(LATEST_SCAN["css_files"]) +
        len(LATEST_SCAN["fonts"]),
        len(LATEST_SCAN["blocked_resources"]),
        CHART_DIR
    )
    generate_security_radar(LATEST_SCAN["csp_rule"], CHART_DIR)


    html_content = render_template(
        "report.html",
        base_path=BASE_DIR,

        url=LATEST_SCAN["url"],
        scan_date=LATEST_SCAN["scan_date"],
        csp_rule=LATEST_SCAN["csp_rule"],

        scripts=LATEST_SCAN["scripts"],
        images=LATEST_SCAN["images"],
        css_files=LATEST_SCAN["css_files"],
        fonts=LATEST_SCAN["fonts"],
        blocked_resources=LATEST_SCAN["blocked_resources"],

        strength_score=LATEST_SCAN["strength_score"],
        baseline_score=LATEST_SCAN["baseline_score"],
        readability_score=LATEST_SCAN["readability_score"],

        csp_explanations=LATEST_SCAN["csp_explanations"],
        resource_analysis=LATEST_SCAN["resource_analysis"]
    )

    HTML(string=html_content, base_url=BASE_DIR).write_pdf(PDF_PATH)

    return send_file(PDF_PATH, mimetype="application/pdf")

@app.route("/send-report-email", methods=["POST"])
def send_report_email():

    if not LATEST_SCAN:
        return {"status": "error", "message": "No scan data available"}, 400

    name = request.form.get("name")
    email = request.form.get("email")

    # ---- EMAIL VALIDATION ----
    if not name:
        return {"status": "error", "message": "Name is required"}, 400

    try:
        validated = validate_email(email)
        email = validated.email  # normalized email

    except EmailNotValidError as e:
        return {"status": "error", "message": str(e)}, 400

    try:

        BASE_DIR = os.path.abspath(os.getcwd())
        PDF_PATH = os.path.join(BASE_DIR, "static", "smartcsp_report.pdf")
        print("SENDGRID KEY:", os.environ.get("SENDGRID_API_KEY"))

        # ---- GENERATE REPORT IF NOT PRESENT ----
        if not os.path.exists(PDF_PATH):

            html_content = render_template(
                "report.html",
                base_path=BASE_DIR,
                **LATEST_SCAN
            )

            HTML(string=html_content, base_url=BASE_DIR).write_pdf(PDF_PATH)

        # ---- PREPARE EMAIL ----
        message = Mail(
            from_email="smartcsp.security@gmail.com",
            to_emails=email,
            subject="SmartCSP Security Report for " + LATEST_SCAN["url"]
        )

        # ---- SENDGRID TEMPLATE ID ----
        message.template_id = os.environ.get("SENDGRID_TEMPLATE_KEY")

        # ---- VARIABLES FOR TEMPLATE ----
        message.dynamic_template_data = {
            "name": name,
            "website": LATEST_SCAN["url"],
            "scan_time": LATEST_SCAN["scan_date"]
        }

        # ---- ATTACH PDF ----
        with open(PDF_PATH, "rb") as f:
            data = f.read()

        encoded_file = base64.b64encode(data).decode()

        attachment = Attachment(
            FileContent(encoded_file),
            FileName("SmartCSP_Report.pdf"),
            FileType("application/pdf"),
            Disposition("attachment")
        )

        message.attachment = attachment

        # ---- SEND EMAIL ----
        sg = SendGridAPIClient(os.environ.get("SENDGRID_API_KEY"))
        sg.send(message)

        return {"status": "success"}

    except Exception as e:
        return {"status": "error", "message": str(e)}, 500


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)