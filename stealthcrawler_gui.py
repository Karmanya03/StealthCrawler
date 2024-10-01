import tkinter as tk
from tkinter import messagebox, scrolledtext
import requests
from bs4 import BeautifulSoup
import random
import re
import time
from fake_useragent import UserAgent
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service

# Proxy list for IP rotation (replace with actual proxies)
proxies_list = [
    'http://47.236.150.172:1080',
    'http://167.71.214.49:8888',
]

# Sensitive data patterns
email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
api_key_patterns = [r'API_KEY', r'secret', r'token', r'authorization']

# Function to extract data from a static page using requests and BeautifulSoup
def crawl_page(url, proxies, headers, result_box):
    try:
        result_box.insert(tk.END, f"Crawling page: {url}\n")
        response = requests.get(url, headers=headers, proxies=proxies, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, 'lxml')

        # Extracting title and links
        title = soup.title.string if soup.title else 'No title found'
        links = [a['href'] for a in soup.find_all('a', href=True)]
        
        result_box.insert(tk.END, f"Page Title: {title}\n")
        result_box.insert(tk.END, f"Number of links found: {len(links)}\n\n")

        for link in links:
            result_box.insert(tk.END, f"{link}\n")

        # Additional features start here
        extract_metadata(soup, result_box)
        extract_emails(soup, result_box)
        check_insecure_headers(url, headers, result_box)
        scan_js_files(url, soup, result_box)
        test_sql_injection(url, headers, result_box)
        test_xss(url, headers, result_box)
        check_open_redirect(url, headers, result_box)

        return links

    except requests.exceptions.RequestException as e:
        result_box.insert(tk.END, f"Error crawling {url}: {e}\n")
        return []

# Function to crawl a page using Selenium for JavaScript-heavy sites
def crawl_with_selenium(url, driver, result_box):
    try:
        result_box.insert(tk.END, f"Crawling with Selenium: {url}\n")
        driver.get(url)
        
        time.sleep(2)  # Give the page time to load

        # Extract title and links
        title = driver.title
        result_box.insert(tk.END, f"Page Title: {title}\n")

        links = [element.get_attribute('href') for element in driver.find_elements(By.TAG_NAME, 'a') if element.get_attribute('href')]
        result_box.insert(tk.END, f"Number of links found: {len(links)}\n\n")

        for link in links:
            result_box.insert(tk.END, f"{link}\n")

        return links

    except Exception as e:
        result_box.insert(tk.END, f"Error crawling {url}: {e}\n")
        return []

# Function to run the crawler based on user input from the GUI
def run_crawler(url, use_selenium, result_box):
    user_agent = UserAgent()
    headers = {'User-Agent': user_agent.random}

    proxy = random.choice(proxies_list)
    proxies = {'http': proxy, 'https': proxy}

    delay = random.uniform(1, 4)
    result_box.insert(tk.END, f"Sleeping for {delay:.2f} seconds before crawling...\n")
    result_box.update()
    time.sleep(delay)

    if use_selenium:
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')  # Headless mode (no UI)
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        driver = webdriver.Chrome(service=Service('/usr/local/bin/chromedriver'), options=options)

        crawl_with_selenium(url, driver, result_box)
        driver.quit()  # Close the browser when done
    else:
        crawl_page(url, proxies, headers, result_box)

# 1. Metadata extraction
def extract_metadata(soup, result_box):
    meta_tags = soup.find_all('meta')
    result_box.insert(tk.END, "\n[Metadata]\n")
    for meta in meta_tags:
        result_box.insert(tk.END, f"Meta Tag: {meta.attrs}\n")

# 2. Extract emails
def extract_emails(soup, result_box):
    emails = set(re.findall(email_pattern, soup.text))
    if emails:
        result_box.insert(tk.END, "\n[Emails]\n")
        for email in emails:
            result_box.insert(tk.END, f"Email found: {email}\n")

# 3. SQL Injection Testing
def test_sql_injection(url, headers, result_box):
    sqli_payloads = ["' OR '1'='1", "' AND 1=1--", "' OR '1'='1'--"]
    result_box.insert(tk.END, "\n[SQL Injection Testing]\n")
    for payload in sqli_payloads:
        test_url = f"{url}?q={payload}"
        result_box.insert(tk.END, f"Testing SQLi: {test_url}\n")
        try:
            response = requests.get(test_url, headers=headers)
            if "error in your SQL syntax" in response.text.lower():
                result_box.insert(tk.END, f"Possible SQLi vulnerability at {test_url}\n")
        except requests.exceptions.RequestException as e:
            result_box.insert(tk.END, f"Error testing {test_url}: {e}\n")

# 4. XSS Injection Testing
def test_xss(url, headers, result_box):
    xss_payloads = ['<script>alert(1)</script>', '<img src="x" onerror="alert(1)">']
    result_box.insert(tk.END, "\n[XSS Injection Testing]\n")
    for payload in xss_payloads:
        test_url = f"{url}?q={payload}"
        result_box.insert(tk.END, f"Testing XSS: {test_url}\n")
        try:
            response = requests.get(test_url, headers=headers)
            if payload in response.text:
                result_box.insert(tk.END, f"Possible XSS vulnerability at {test_url}\n")
        except requests.exceptions.RequestException as e:
            result_box.insert(tk.END, f"Error testing {test_url}: {e}\n")

# 5. Insecure HTTP Headers Detection
def check_insecure_headers(url, headers, result_box):
    try:
        response = requests.get(url, headers=headers)
        missing_headers = []
        if 'x-frame-options' not in response.headers:
            missing_headers.append("X-Frame-Options missing (Clickjacking vulnerability)")
        if 'content-security-policy' not in response.headers:
            missing_headers.append("Content-Security-Policy missing (XSS protection)")
        if 'strict-transport-security' not in response.headers:
            missing_headers.append("Strict-Transport-Security missing (No HSTS)")

        result_box.insert(tk.END, "\n[Security Headers Check]\n")
        if missing_headers:
            for header in missing_headers:
                result_box.insert(tk.END, f"{header}\n")
        else:
            result_box.insert(tk.END, "All critical headers are present.\n")
    except requests.exceptions.RequestException as e:
        result_box.insert(tk.END, f"Error checking headers for {url}: {e}\n")

# 6. JavaScript File Analysis
def scan_js_files(url, soup, result_box):
    js_files = [script['src'] for script in soup.find_all('script') if script.get('src')]
    result_box.insert(tk.END, "\n[JavaScript File Analysis]\n")
    for js in js_files:
        try:
            response = requests.get(js)
            if response.status_code == 200:
                if any(key in response.text for key in api_key_patterns):
                    result_box.insert(tk.END, f"Potential sensitive data found in {js}\n")
        except:
            result_box.insert(tk.END, f"Failed to scan {js}\n")

# 7. Open Redirect Testing
def check_open_redirect(url, headers, result_box):
    payloads = ['https://evil.com', 'http://malicious.com']
    result_box.insert(tk.END, "\n[Open Redirect Testing]\n")
    for payload in payloads:
        redirect_url = f"{url}?redirect={payload}"
        try:
            response = requests.get(redirect_url, headers=headers, allow_redirects=False)
            if response.status_code in [301, 302] and response.headers.get('Location') == payload:
                result_box.insert(tk.END, f"Possible open redirect vulnerability at {redirect_url}\n")
        except requests.exceptions.RequestException as e:
            result_box.insert(tk.END, f"Error checking open redirect for {url}: {e}\n")

# Function triggered when the 'Start Crawl' button is clicked
def start_crawl():
    target_url = url_entry.get()

    if not target_url.startswith('http'):
        messagebox.showerror("Invalid URL", "Please enter a valid URL (starting with http:// or https://)")
        return

    result_box.delete('1.0', tk.END)
    use_selenium = selenium_var.get()
    run_crawler(target_url, use_selenium, result_box)

# GUI Setup using Tkinter
app = tk.Tk()
app.title("Advanced Stealth Web Crawler")
app.geometry('600x600')

tk.Label(app, text="Target URL:").pack(pady=5)
url_entry = tk.Entry(app, width=50)
url_entry.pack(pady=5)

selenium_var = tk.IntVar()
tk.Checkbutton(app, text="Use Selenium (for JavaScript-heavy sites)", variable=selenium_var).pack(anchor='w')

tk.Label(app, text="Results:").pack(pady=5)
result_box = scrolledtext.ScrolledText(app, height=20, width=70)
result_box.pack(pady=5)

start_button = tk.Button(app, text="Start Crawl", command=start_crawl)
start_button.pack(pady=10)

app.mainloop()
