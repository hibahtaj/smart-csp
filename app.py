from flask import Flask, render_template, request
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from urllib.parse import urljoin
from csp_generator.generate_csp import generate_csp
from sandbox.test_csp import test_csp

app = Flask(__name__)

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

            # Extract scripts
            scripts = [urljoin(driver.current_url, s.get_attribute('src'))
                       for s in driver.find_elements("tag name", "script")
                       if s.get_attribute('src')]

            # Extract images
            images = [urljoin(driver.current_url, i.get_attribute('src'))
                      for i in driver.find_elements("tag name", "img")
                      if i.get_attribute('src')]

            # Extract CSS files
            css_files = [urljoin(driver.current_url, c.get_attribute('href'))
                         for c in driver.find_elements("tag name", "link")
                         if c.get_attribute('rel') == 'stylesheet' and c.get_attribute('href')]

            # Extract fonts (from link hrefs containing 'font')
            fonts = [urljoin(driver.current_url, f.get_attribute('href'))
                     for f in driver.find_elements("tag name", "link")
                     if f.get_attribute('href') and 'font' in f.get_attribute('href')]

            driver.quit()

            # Generate clean CSP header
            csp_rule = generate_csp(scripts, images, css_files, fonts)

            # Run sandbox test
            blocked_resources = test_csp(url, csp_rule)

            # Render results page
            return render_template('results.html',
                                   url=url,
                                   scripts=scripts,
                                   images=images,
                                   css_files=css_files,
                                   fonts=fonts,
                                   csp_rule=csp_rule,
                                   blocked_resources=blocked_resources)

        except Exception as e:
            return f"Error fetching website: {e}"

    # GET request → show index page
    return render_template('index.html')


if __name__ == "__main__":
    app.run(debug=True)

