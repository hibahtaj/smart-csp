from selenium import webdriver
from selenium.webdriver.chrome.options import Options

def test_csp(driver, url, csp_rule):

    driver.execute_cdp_cmd(
        "Network.setExtraHTTPHeaders",
        {"headers": {"Content-Security-Policy": csp_rule}}
    )

    driver.get(url)

    blocked_resources = []

    try:
        logs = driver.get_log('browser')
        for entry in logs:
            if "CSP" in entry['message'] or "Content Security Policy" in entry["message"]:
                blocked_resources.append(entry['message'])
    except Exception:
        # Logs may not be available
        pass
    
    return blocked_resources

# Example usage for testing independently
if __name__ == "__main__":
    test_url = "https://example.com"
    test_rule = "script-src 'self'; img-src 'self';"
    blocked = test_csp(test_url, test_rule)
    print(blocked)
