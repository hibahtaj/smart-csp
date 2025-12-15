from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

app = Flask(__name__)

# Helper: get domain from URL
def get_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return ''

# Generate CSP header from scanned resources
def generate_csp(scripts, images, css_files, fonts):
    script_domains = set(get_domain(s) for s in scripts)
    img_domains = set(get_domain(i) for i in images)
    css_domains = set(get_domain(c) for c in css_files)
    font_domains = set(get_domain(f) for f in fonts)

    csp = "Content-Security-Policy: "
    csp += f"script-src {' '.join(script_domains)}; "
    csp += f"img-src {' '.join(img_domains)}; "
    csp += f"style-src {' '.join(css_domains)}; "
    csp += f"font-src {' '.join(font_domains)};"

    return csp

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('website_url')

        try:
            # Fetch website HTML
            response = requests.get(url)
            html = response.text

            # Parse HTML
            soup = BeautifulSoup(html, 'html.parser')

            # Extract resources
            scripts = [urljoin(url, tag.get('src')) for tag in soup.find_all('script') if tag.get('src')]
            images = [urljoin(url, tag.get('src')) for tag in soup.find_all('img') if tag.get('src')]
            css_files = [urljoin(url, tag.get('href')) for tag in soup.find_all('link', rel='stylesheet') if tag.get('href')]
            fonts = [urljoin(url, tag.get('href')) for tag in soup.find_all('link') if tag.get('href') and 'font' in tag.get('href')]

            # Generate CSP
            csp_rule = generate_csp(scripts, images, css_files, fonts)

            return render_template('results.html', url=url, scripts=scripts, images=images,
                                   css_files=css_files, fonts=fonts, csp_rule=csp_rule)
        except Exception as e:
            return f"Error fetching website: {e}"

    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True)
