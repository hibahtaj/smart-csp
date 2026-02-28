from flask import Flask, render_template, request, send_file
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

from utils.scoring import compute_strength_score, compute_baseline_score, compute_readability_score, generate_block_summary
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

            allowed_count = len(scripts) + len(images) + len(css_files) + len(fonts)
            blocked_count = len(blocked_resources)

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
                "blocked_resources": blocked_resources,
                "strength_score": smart_score,
                "baseline_score": baseline_score,
                "readability_score": readability_score,
                "block_summary": block_summary,
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M")
            })

            # ---- RENDER RESULTS PAGE ----
            return render_template(
                "results.html",
                url=url,
                csp_rule=csp_rule,
                strength_score=smart_score,
                readability_score=readability_score,
                block_summary=block_summary
            )

        except Exception as e:
            return f"Error fetching website: {e}"

    return render_template('index.html')

@app.route("/report/preview")
def report_preview():
    if not LATEST_SCAN:
        return "No scan data available", 400

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
        **LATEST_SCAN
    )

    from weasyprint import HTML
    HTML(string=html_content, base_url=BASE_DIR).write_pdf(PDF_PATH)

    return send_file(PDF_PATH, mimetype="application/pdf")

@app.route("/report/download")
def report_download():
    if not LATEST_SCAN:
        return "No scan data available", 400

    BASE_DIR = os.path.abspath(os.getcwd())
    CHART_DIR = os.path.join(BASE_DIR, "static", "charts")
    PDF_PATH = os.path.join(BASE_DIR, "static", "smartcsp_report.pdf")

    # Ensure charts exist (in case user skips preview)
    generate_strength_donut(LATEST_SCAN["strength_score"], CHART_DIR)
    # generate_strength_comparison(
    #     LATEST_SCAN["baseline_score"],
    #     LATEST_SCAN["strength_score"],
    #     CHART_DIR
    # )
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
        **LATEST_SCAN
    )

    HTML(string=html_content, base_url=BASE_DIR).write_pdf(PDF_PATH)

    return send_file(PDF_PATH, mimetype="application/pdf")


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)