# SmartCSP: CSP Generator, Tester, and Optimizer

SmartCSP is a web-based security tool that automates the generation, validation, and analysis of Content Security Policies (CSP). It dynamically scans a website’s runtime resources, constructs a tailored CSP, evaluates its effectiveness through sandbox testing, and produces a structured report with actionable deployment guidance for developers.

---

## Getting Started

These instructions will help you set up SmartCSP on your local machine for development and testing. Refer to the Deployment section for information on hosting the application in a production environment.

---

### Prerequisites

Requirements for running the project:

- Python 3.8 or higher  
- Google Chrome (for Selenium execution)  
- ChromeDriver (managed automatically via webdriver-manager)  
- pip (Python package manager)  

---

### Installing
The application is designed to run in a containerized environment (Azure App Service). Local execution may require additional configuration for Selenium and Chrome.

Follow these steps to run locally:

Clone the repository:

    git clone https://github.com/hibahtaj/smart-csp
    cd smartcsp

Create a virtual environment:

    python -m venv venv
    source venv/bin/activate
    # Windows: venv\Scripts\activate

Install dependencies:

    pip install -r requirements.txt

Run the application:

    python main.py

Open the application in a browser:

    http://localhost:5000

Enter a URL, generate a CSP, and view the analysis and report.

Note: For best results, use the deployed version as it mirrors the production environment.

---

## Running the tests

Testing is performed through functional and scenario-based validation of the system.


### Sample Tests

The system was tested using representative website scenarios:

- Inline script-heavy pages to validate nonce guidance  
- External resource pages to validate domain extraction  
- Mixed content pages to verify combined handling  
- Minimal pages to test default CSP generation  

All test implementations and test cases can be found here:

https://github.com/bavRaghu/smart-csp-tests

Example:

    Input: website with inline scripts
    Expected: CSP generated without unsafe-inline and nonce guidance displayed
---
## Features

### Dynamic Resource Extraction
- Uses a headless browser (Selenium with Chrome) to analyze websites at runtime  
- Extracts scripts, images, stylesheets, fonts, objects, and frames directly from the DOM  

### Automated CSP Generation
- Generates Content Security Policies based on observed resource usage  
- Constructs directive-specific rules (`script-src`, `img-src`, `style-src`, `font-src`, `frame-src`)    

### CSP Validation and Sandbox Testing
- Applies the generated CSP within a controlled browser environment  
- Detects blocked resources and identifies policy violations  
- Ensures that the generated CSP maintains both security and functionality  

### Inline Script Handling and Nonce Support
- Detects the presence of inline scripts during resource extraction 
- Provides structured guidance for implementing nonce-based CSP  
- Includes backend-specific examples for securely generating and applying dynamic nonces  
- Ensures that nonce usage aligns with best practices (per-request generation, no reuse)  

### Security Analysis and Scoring
- Evaluates CSP strength based on known security heuristics  
- Computes:
  - Strength score  
  - Readability score  
  - Baseline comparison against weak/default policies  
- Highlights potential risks such as wildcard usage or insecure directives  

### Standards and Compliance Checking
- Validates generated CSP against OWASP security guidelines  
- Ensures adherence to modern web security standards  

### Reporting Module
- Generates structured PDF reports using HTML templates  
- Includes:
  - Generated CSP  
  - Resource analysis  
  - Blocked resources  
  - Security scores and compliance results  
  - Visual charts and breakdowns  
  - Deployment and integration guidance  
- Supports both preview and downloadable report formats  

### Email-Based Report Delivery
- Sends generated reports directly to users via SMTP  
- Includes input validation for user-provided details  
- Attaches pre-generated reports to minimize processing overhead  

### Performance Optimization
- Implements URL-based caching using hashing to avoid repeated scans  
- Skips Selenium execution for previously scanned websites  
- Uses optimized headless browser configuration to reduce resource usage  
- Applies eager page load strategy to minimize scan time  

### Fault Tolerance and Robustness
- Uses safe data access patterns to prevent runtime errors  
- Handles missing or incomplete scan data gracefully  
- Includes exception handling for browser execution and CSP testing  

### Developer-Focused Output
- Provides clear explanations of CSP directives  
- Includes actionable deployment guidance for integrating CSP into applications  
- Designed to bridge the gap between security recommendations and real-world implementation  

---
## Built With

- Flask (Python web framework)  
- Selenium (browser automation)  
- WeasyPrint (PDF generation)  
- HTML, CSS, JavaScript (frontend)  
- Microsoft Azure & Docker (deployment)  
- GitHub (version control and CI/CD integration)  

---

## Deployment

The application is deployed as a containerized Flask service on Microsoft Azure App Service.

Deployment process:

- Code is pushed to GitHub  
- Azure is integrated with the repository  
- On updates to the main branch:
  - Latest code is pulled  
  - Application is rebuilt  
  - Service is redeployed automatically  

Containerization ensures consistent runtime behavior and isolates dependencies such as Selenium and Chrome.

### Live Application

The application is deployed and accessible at:

https://smartcsp-dev.azurewebsites.net/

Note: The deployed version runs in a containerized environment and may have limited resources depending on cloud constraints.

---
