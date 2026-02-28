def compute_strength_score(csp_rule: str) -> int:
    score = 100

    if "unsafe-inline" in csp_rule:
        score -= 25
    if "unsafe-eval" in csp_rule:
        score -= 20
    if "*" in csp_rule:
        score -= 20
    if "nonce-" not in csp_rule:
        score -= 15
    if "script-src" not in csp_rule:
        score -= 20

    return max(score, 0)


def compute_baseline_score(existing_csp: str | None) -> int:
    if not existing_csp:
        return 10  # no CSP at all
    score = 40
    if "unsafe-inline" in existing_csp:
        score -= 10
    if "*" in existing_csp:
        score -= 10
    return max(score, 0)

def compute_readability_score(csp_rule: str) -> int:
    """
    Higher score = easier to read and maintain CSP
    """
    directives = [d.strip() for d in csp_rule.split(";") if d.strip()]

    score = 100

    if len(directives) > 10:
        score -= 15
    if "*" in csp_rule:
        score -= 20
    if "unsafe-inline" in csp_rule:
        score -= 25
    if "nonce-" in csp_rule:
        score += 5

    return max(30, min(score, 100))


def generate_block_summary(csp_rule: str) -> list[str]:
    """
    Human-readable explanation of what the CSP blocks
    """
    summary = []

    if "unsafe-inline" not in csp_rule:
        summary.append(
            "Inline scripts without explicit authorization would be blocked."
        )

    if "*" not in csp_rule:
        summary.append(
            "Resources from unspecified or untrusted domains would be blocked."
        )

    if "object-src 'none'" in csp_rule:
        summary.append(
            "All plugin-based content such as Flash or embedded objects would be blocked."
        )

    if "require-trusted-types-for 'script'" in csp_rule:
        summary.append(
            "DOM-based script injection would be restricted through Trusted Types enforcement."
        )

    if not summary:
        summary.append(
            "No major restrictions detected; the policy is relatively permissive."
        )

    return summary

def generate_csp_explanations(csp_rule: str):
    explanations = []

    if "script-src" in csp_rule:
        explanations.append((
            "script-src",
            "Restricts script execution to explicitly allowed sources, significantly reducing the risk of cross-site scripting (XSS) attacks."
        ))

    if "style-src" in csp_rule:
        explanations.append((
            "style-src",
            "Limits stylesheet loading to known sources, preventing malicious style injection."
        ))

    if "img-src" in csp_rule:
        explanations.append((
            "img-src",
            "Restricts image loading to trusted domains, reducing the risk of data exfiltration through image requests."
        ))

    if "font-src" in csp_rule:
        explanations.append((
            "font-src",
            "Controls the sources from which fonts can be loaded, preventing unauthorized font injection."
        ))

    if "object-src 'none'" in csp_rule:
        explanations.append((
            "object-src",
            "Disables plugin-based content such as Flash or embedded objects, which are common attack vectors."
        ))

    if "require-trusted-types-for 'script'" in csp_rule:
        explanations.append((
            "trusted-types",
            "Enforces Trusted Types to mitigate DOM-based script injection vulnerabilities."
        ))

    return explanations
from urllib.parse import urlparse

def get_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return None


def generate_advanced_resource_analysis(
    scripts, images, css_files, fonts, blocked_resources
):
    analysis = {}

    # ---- SCRIPT ANALYSIS ----
    if scripts:
        domains = set(get_domain(s) for s in scripts if s)
        analysis["script-src"] = {
            "analysis": (
                f"{len(scripts)} script resources were detected across "
                f"{len(domains)} unique domains. Scripts represent the highest "
                "risk category as they execute arbitrary JavaScript code in the "
                "browser. SmartCSP restricts script execution strictly to observed "
                "sources to minimize XSS and injection risks."
            ),
            "resources": scripts
        }

    # ---- IMAGE ANALYSIS ----
    if images:
        domains = set(get_domain(i) for i in images if i)
        analysis["img-src"] = {
            "analysis": (
                f"{len(images)} image resources were observed from "
                f"{len(domains)} domains. While images pose lower execution risk, "
                "their sources are constrained to prevent data exfiltration, "
                "tracking abuse, and malicious payload delivery."
            ),
            "resources": images
        }

    # ---- STYLE ANALYSIS ----
    if css_files:
        domains = set(get_domain(c) for c in css_files if c)
        analysis["style-src"] = {
            "analysis": (
                f"{len(css_files)} stylesheet resources were identified. "
                "Restricting style sources prevents unauthorized CSS injection "
                "and mitigates style-based side-channel attacks."
            ),
            "resources": css_files
        }

    # ---- FONT ANALYSIS ----
    if fonts:
        domains = set(get_domain(f) for f in fonts if f)
        analysis["font-src"] = {
            "analysis": (
                f"{len(fonts)} font resources were detected. Fonts are limited to "
                "trusted providers to ensure consistent rendering and prevent "
                "unauthorized font loading."
            ),
            "resources": fonts
        }
    return analysis