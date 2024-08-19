import whois
import requests
from bs4 import BeautifulSoup
import socket
import ssl
import OpenSSL
from urllib.parse import urlparse
import dns.resolver
import concurrent.futures
import json
import re
from user_agents import parse
import tldextract
import shodan
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.units import inch
import builtwith
import subprocess

def load_secrets(filename='secrets.json'):
    with open(filename, 'r') as f:
        return json.load(f)

def get_website_info(url, shodan_api_key):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
    domain = domain.replace('www.', '')
    ext = tldextract.extract(domain)
    root_domain = f"{ext.domain}.{ext.suffix}"

    info = {
        'url': url,
        'domain': domain,
        'root_domain': root_domain,
        'whois': None,
        'ip': None,
        'reverse_dns': None,
        'server': None,
        'technologies': [],
        'headers': {},
        'dns': {},
        'ssl': None,
        'shodan': None,
        'wappalyzer': None,
        'traceroute': None,
    }

    try:
        info['whois'] = whois.whois(domain)
    except Exception as e:
        print(f"WHOIS error for {domain}: {e}")

    try:
        info['ip'] = socket.gethostbyname(domain)
        info['reverse_dns'] = socket.gethostbyaddr(info['ip'])[0]
    except Exception as e:
        print(f"IP/Reverse DNS error for {domain}: {e}")

    try:
        response = requests.get(f"https://{domain}", timeout=10, allow_redirects=True)
        info['headers'] = dict(response.headers)
        info['server'] = response.headers.get('Server')
        info['status_code'] = response.status_code
        info['final_url'] = response.url

        ua_string = response.request.headers.get('User-Agent')
        user_agent = parse(ua_string)
        info['user_agent'] = {
            'browser': user_agent.browser.family,
            'os': user_agent.os.family,
            'device': user_agent.device.family
        }

        soup = BeautifulSoup(response.text, 'html.parser')
        if soup.find(attrs={"name": "generator"}):
            info['technologies'].append(soup.find(attrs={"name": "generator"})['content'])
        if 'WordPress' in response.text:
            info['technologies'].append('WordPress')
        if 'Joomla' in response.text:
            info['technologies'].append('Joomla')

        security_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-XSS-Protection']
        for header in security_headers:
            if header in response.headers:
                info['technologies'].append(f"{header} implemented")

        info['technologies'] = builtwith.parse(url)

    except Exception as e:
        print(f"HTTP request error for {domain}: {e}")

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
        
        cert_bin = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ssl.get_server_certificate((domain, 443))))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)

        info['ssl'] = {
            'version': s.version(),
            'issuer': dict(x[0] for x in cert['issuer']),
            'subject': dict(x[0] for x in cert['subject']),
            'expiration': cert['notAfter'],
            'serial_number': x509.get_serial_number(),
            'signature_algorithm': x509.get_signature_algorithm().decode(),
        }
    except Exception as e:
        print(f"SSL error for {domain}: {e}")

    try:
        for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']:
            answers = dns.resolver.resolve(domain, qtype)
            info['dns'][qtype] = [str(rdata) for rdata in answers]
    except Exception as e:
        print(f"DNS error for {domain}: {e}")

    try:
        shodan_api = shodan.Shodan(shodan_api_key)
        shodan_info = shodan_api.host(info['ip'])
        info['shodan'] = {
            'os': shodan_info.get('os'),
            'ports': shodan_info.get('ports'),
            'vulns': shodan_info.get('vulns'),
        }
    except Exception as e:
        print(f"Shodan error for {domain}: {e}")

    try:
        traceroute_output = subprocess.check_output(['traceroute', domain], universal_newlines=True)
        info['traceroute'] = traceroute_output.strip().split('\n')
    except Exception as e:
        print(f"Traceroute error for {domain}: {e}")

    return info

def create_pdf_report(results, filename="website_report.pdf"):
    doc = SimpleDocTemplate(filename, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    elements = []
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(name='TableCell', parent=styles['Normal'], fontSize=8, leading=10, alignment=TA_LEFT))

    elements.append(Paragraph("Website Analysis Report", styles['Title']))
    elements.append(Spacer(1, 12))

    for result in results:
        elements.append(Paragraph(f"Information for {result['url']}", styles['Heading1']))
        elements.append(Spacer(1, 6))

        data = [
            ["Domain", result['domain']],
            ["Root Domain", result['root_domain']],
            ["IP", result['ip']],
            ["Reverse DNS", result['reverse_dns']],
            ["Server", result['server']],
            ["Technologies", ", ".join(result['technologies'])],
            ["WHOIS", Paragraph(str(result['whois']), styles['TableCell'])],
            ["SSL", Paragraph(str(result.get('ssl', 'N/A')), styles['TableCell'])],
            ["DNS", Paragraph(str(result['dns']), styles['TableCell'])],
            ["Headers", Paragraph(str(result['headers']), styles['TableCell'])],
            ["Shodan", Paragraph(str(result['shodan']), styles['TableCell'])],
            ["Traceroute", Paragraph("\n".join(result['traceroute']) if result['traceroute'] else "N/A", styles['TableCell'])]
        ]

        table = Table(data, colWidths=[1.5*inch, 5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('BACKGROUND', (1, 1), (-1, -1), colors.beige),
            ('BOX', (0, 0), (-1, -1), 1, colors.black),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 12))

    doc.build(elements)

def main():
    secrets = load_secrets()
    websites = secrets['websites']
    shodan_api_key = secrets['shodan_api_key']

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(lambda url: get_website_info(url, shodan_api_key), websites))

    create_pdf_report(results)

    print("PDF report has been generated: website_report.pdf")

    with open('website_info.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)

if __name__ == "__main__":
    main()