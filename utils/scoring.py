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