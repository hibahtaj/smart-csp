from urllib.parse import urlparse

def get_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return ''

def generate_csp(scripts, images, css_files, fonts):
    directives = []

    script_domains = set(get_domain(s) for s in scripts if s)
    if script_domains:
        directives.append(f"script-src {' '.join(script_domains)}")

    img_domains = set(get_domain(i) for i in images if i)
    if img_domains:
        directives.append(f"img-src {' '.join(img_domains)}")

    css_domains = set(get_domain(c) for c in css_files if c)
    if css_domains:
        directives.append(f"style-src {' '.join(css_domains)}")

    font_domains = set(get_domain(f) for f in fonts if f)
    if font_domains:
        directives.append(f"font-src {' '.join(font_domains)}")

    return "Content-Security-Policy: " + "; ".join(directives) + ";"
