import secrets
from urllib.parse import urlparse

def get_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return None


def generate_csp(scripts, images, css_files, fonts, objects=None, frames=None, has_inline_scripts=False):
    directives = []

    nonce = None

    # script-src
    script_domains = set(get_domain(s) for s in scripts if get_domain(s))
    
    if has_inline_scripts:
        nonce = secrets.token_urlsafe(16)
        script_domains.add(f"'nonce-{nonce}")

    if script_domains:
        script_src = ["'self'"] + sorted(d for d in script_domains if d)
        directives.append(f"script-src {' '.join(script_src)}")
    # img-src
    img_domains = set(
        get_domain(i) for i in images if i
    )
    if img_domains:
        img_src = ["'self'"] + sorted(d for d in img_domains if d)
        directives.append(f"img-src {' '.join(img_src)}")

    # style-src
    css_domains = set(
        get_domain(c) for c in css_files if c
    )
    if css_domains:
        style_src = ["'self'"] + sorted(d for d in css_domains if d)
        directives.append(f"style-src {' '.join(style_src)}")

    # font-src
    font_domains = set(
        get_domain(f) for f in fonts if f
    )
    if font_domains:
        font_src = ["'self'"] + sorted(d for d in font_domains if d)
        directives.append(f"font-src {' '.join(font_src)}")

    # object-src
    if objects:
        object_domains = set(get_domain(o) for o in objects if o)
        if object_domains:
            directives.append(f"object-src {' '.join(object_domains)}")
        else:
            directives.append("object-src 'none'")
    else:
        directives.append("object-src 'none'")

    #frame-src
    if frames:
        
        frame_src = set(get_domain(f) for f in frames if f)
        if frame_src:
            directives.append(f"frame-src {' '.join(frame_src)}")
        else:
            directives.append("frame-src 'none'")
    else:
        directives.append("frame-src 'none'")

    if not has_inline_scripts:
        directives.append("require-trusted-types-for 'script'")

    return {
        "csp": "Content-Security-Policy: " + "; ".join(directives) + ";",
        "nonce": nonce
    }
