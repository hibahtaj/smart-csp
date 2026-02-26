import matplotlib
matplotlib.use("Agg")

from constants import CHART_DIR
import matplotlib.pyplot as plt
import numpy as np
import os


def save_path(filename):
    return os.path.join(CHART_DIR, filename)

def generate_strength_donut(score):
    plt.figure(figsize=(4, 4))
    plt.pie(
        [score, 100 - score],
        startangle=90,
        colors=["#ABBB9C", "#e6e6e6"],
        wedgeprops={"width": 0.35}
    )
    plt.text(0, 0, f"{score}%", ha="center", va="center", fontsize=18)
    plt.title("CSP Strength Score")

    plt.savefig(save_path("strength_donut.png"), bbox_inches="tight")
    plt.close()

def generate_strength_comparison(original, smart):
    labels = ["Original CSP", "SmartCSP"]
    values = [original, smart]

    plt.figure(figsize=(5, 3))
    colours=["#ABBB9C", "#495043"]
    plt.bar(labels, values, color=colours)
    plt.ylim(0, 100)
    plt.ylabel("Strength Score")
    plt.title("CSP Strength Comparison")

    plt.savefig(save_path("strength_comparison_bar.png"), bbox_inches="tight")
    plt.close()

def generate_resource_breakdown(scripts, images, css_files, fonts):
    labels = ["Scripts", "Images", "CSS", "Fonts"]
    counts = [len(scripts), len(images), len(css_files), len(fonts)]

    plt.figure(figsize=(4, 4))
    colours = ["#D1E4C0", "#ABBB9C", "#727C68", "#495043"]
    plt.pie(counts, labels=labels, autopct="%1.0f%%", colors=colours)
    plt.title("Resource Breakdown")

    plt.savefig(save_path("resource_breakdown_pie.png"), bbox_inches="tight")
    plt.close()

def generate_test_results(allowed_count, blocked_count):
    labels = ["Allowed", "Blocked"]
    values = [allowed_count, blocked_count]
    colours=["#ABBB9C", "#495043"]
    plt.figure(figsize=(4, 3))
    plt.bar(labels, values, color=colours)
    plt.title("Sandbox Test Results")

    plt.savefig(save_path("test_results_bar.png"), bbox_inches="tight")
    plt.close()

def generate_security_radar(csp_rule: str):
    import matplotlib.pyplot as plt
    import numpy as np
    import os

    labels = [
        "Script Safety",
        "Inline Protection",
        "Source Specificity",
        "Directive Coverage",
        "XSS Mitigation"
    ]

    # ---- HEURISTIC SCORES ----
    script_safety = 90 if "script-src" in csp_rule else 40

    inline_protection = 85
    if "unsafe-inline" in csp_rule:
        inline_protection = 25
    elif "nonce-" in csp_rule:
        inline_protection = 90

    specificity = 85 if "*" not in csp_rule else 30

    directive_count = len([d for d in csp_rule.split(";") if d.strip()])
    coverage = min(100, 40 + directive_count * 10)

    xss_mitigation = 90
    if "unsafe-inline" in csp_rule:
        xss_mitigation -= 40
    if "object-src 'none'" not in csp_rule:
        xss_mitigation -= 20

    values = [
        script_safety,
        inline_protection,
        specificity,
        coverage,
        max(xss_mitigation, 20)
    ]

    values += values[:1]
    angles = np.linspace(0, 2 * np.pi, len(labels), endpoint=False)
    angles = np.concatenate([angles, [angles[0]]])

    # ---- PLOT ----
    plt.figure(figsize=(5.5, 5.5))
    ax = plt.subplot(111, polar=True)

    # Line (dark green)
    ax.plot(
        angles,
        values,
        linewidth=2.5,
        color="#495043"
    )

    # Fill (light green)
    ax.fill(
        angles,
        values,
        color="#ABBB9C",
        alpha=0.45
    )

    # Axis / grid styling
    ax.set_thetagrids(angles[:-1] * 180 / np.pi, labels)
    ax.set_ylim(0, 100)
    ax.set_yticks([20, 40, 60, 80])
    ax.set_yticklabels(["20", "40", "60", "80"], fontsize=9, color="#666")

    ax.grid(color="#cfd6c9", linewidth=0.8)

    ax.spines["polar"].set_color("#cfd6c9")

    ax.set_title(
        "SmartCSP Security Profile",
        pad=22,
        fontsize=14,
        color="#495043"
    )

    output_path = os.path.join("static", "charts", "security_radar.png")
    plt.savefig(output_path, bbox_inches="tight", facecolor="#fafaf7")
    plt.close()

