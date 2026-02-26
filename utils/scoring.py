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