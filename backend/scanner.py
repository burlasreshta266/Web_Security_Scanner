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
        self.vulnerabilities = List[Dict] = {}
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