import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import os


def save_path(chart_dir, filename):
    os.makedirs(chart_dir, exist_ok=True)
    return os.path.join(chart_dir, filename)


def generate_strength_donut(score, chart_dir):
    plt.figure(figsize=(4, 4))
    plt.pie(
        [score, 100 - score],
        startangle=90,
        colors=["#ABBB9C", "#e6e6e6"],
        wedgeprops={"width": 0.35}
    )
    plt.text(0, 0, f"{score}%", ha="center", va="center", fontsize=18)
    plt.title("CSP Strength Score")

    plt.savefig(save_path(chart_dir, "strength_donut.png"), bbox_inches="tight")
    plt.close()


def generate_strength_comparison(original, smart, chart_dir):
    labels = ["Original CSP", "SmartCSP"]
    values = [original, smart]

    plt.figure(figsize=(5, 3))
    plt.bar(labels, values, color=["#ABBB9C", "#495043"])
    plt.ylim(0, 100)
    plt.ylabel("Strength Score")
    plt.title("CSP Strength Comparison")

    plt.savefig(save_path(chart_dir, "strength_comparison_bar.png"), bbox_inches="tight")
    plt.close()


def generate_resource_breakdown(scripts, images, css_files, fonts, chart_dir):
    labels = ["Scripts", "Images", "CSS", "Fonts"]
    counts = [len(scripts), len(images), len(css_files), len(fonts)]

    plt.figure(figsize=(4, 4))
    colours = ["#D1E4C0", "#ABBB9C", "#727C68", "#495043"]
    plt.pie(counts, labels=labels, autopct="%1.0f%%", colors=colours)
    plt.title("Resource Breakdown")

    plt.savefig(save_path(chart_dir, "resource_breakdown_pie.png"), bbox_inches="tight")
    plt.close()


def generate_test_results(allowed_count, blocked_count, chart_dir):
    labels = ["Allowed", "Blocked"]
    values = [allowed_count, blocked_count]

    plt.figure(figsize=(4, 3))
    plt.bar(labels, values, color=["#ABBB9C", "#495043"])
    plt.title("Sandbox Test Results")

    plt.savefig(save_path(chart_dir, "test_results_bar.png"), bbox_inches="tight")
    plt.close()


def generate_security_radar(csp_rule, chart_dir):
    labels = [
        "Script Safety",
        "Inline Protection",
        "Source Specificity",
        "Directive Coverage",
        "XSS Mitigation"
    ]

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

    plt.figure(figsize=(5.5, 5.5))
    ax = plt.subplot(111, polar=True)

    ax.plot(angles, values, linewidth=2.5, color="#495043")
    ax.fill(angles, values, color="#ABBB9C", alpha=0.45)

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

    plt.savefig(
        save_path(chart_dir, "security_radar.png"),
        bbox_inches="tight",
        facecolor="#fafaf7"
    )
    plt.close()

