import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor
import sys
from typing import List, Dict, Set

class Scanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities = List[Dict] = []
        self.session = requests.session

    def normalize_usl(self, url: str):
        normal = urllib.parse.urlparse(url)
        return f"{normal.scheme}://{normal.netloc}{normal.path}"
    

    def crawl(self, url: str, depth: int = 0):
        if depth > self.max_depth or url in self.visited_urls:
            return
        
        try:
            self.visited_urls.add(url)
            response = self.session.get(url, verify=False)
            html = BeautifulSoup(response.text, "html.parser")

            for link in html.find_all("a", href=True):
                rel = link.attrs("href")
                new_url = urllib.parse.urljoin(url, rel)
                if new_url.startswith(self.target_url):
                    self.crawl(new_url, depth+1)

        except Exception as e:
            return f"Error while crawling {url}: {str(e)}"

    
    def check_sql_injection(self, url: str):
        sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]
        sql_errors = ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle']

        for payload in sql_payloads:
            try:
                url_data = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(url_data)

                for param in params:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    new_query = urllib.parse.urlencode(test_params, doseq=True)

                    test_url = urllib.parse.urlunparse(
                        url_data._replace(query=new_query)
                    )
                    response = self.session.get(test_url)
                    if any(error in response.text.lower() for error in sql_errors):
                        self.report_vulnerability({
                            "type": "SQL injection",
                            "url" : url,
                            "parameter" : param,
                            "payload" : payload
                        })
            
            except Exception as e:
                return f"Error checking SQL injection in {url}: {str(e)}"


    def check_xss(self, url: str):
        xss_payloads =  [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

        try:
            for payload in xss_payloads:
                url_data = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(url_data)

                for param in params:
                    test_params = params.copy()
                    test_params[param] = payload
                    new_query = urllib.parse.urlencode(test_params, doseq=True)

                    test_url = urllib.parse.urlunparse(
                        url_data._replace(query=new_query)
                    )
                    response = self.session.get(test_url)
                    if payload in response.text.lower():
                        self.report_vulnerability({
                            "type": "SQL injection",
                            "url" : url,
                            "parameter" : param,
                            "payload" : payload
                        })
            
        except Exception as e:
            return f"Error checking XSS injection in {url}: {str(e)}"


    def check_sensitive_info(self, url: str):
        sensitive_patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'api_key': r'api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1'
        }

        try:
            response = self.session.get(url)

            for info_type, pattern in sensitive_patterns.items():
                matches = re.finditer(pattern, response.text)
                for match in matches:
                    self.report_vulnerability({
                        'type': 'Sensitive Information Exposure',
                        'url': url,
                        'info_type': info_type,
                        'pattern': pattern
                    })

        except Exception as e:
            print(f"Error checking sensitive information on {url}: {str(e)}")


    def report_vulnerability(self, vulnerability: Dict):
        self.vulnerabilities.append(vulnerability)