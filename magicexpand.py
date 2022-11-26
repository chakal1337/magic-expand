import sys
import socket
import threading
import time
import dns.resolver
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import warnings

warnings.filterwarnings("ignore")

commonports = {
 21:"ftp",
 22:"ssh",
 23:"telnet",
 25:"smtp",
 80:"http",
 139:"netbios",
 443:"https",
 445:"smb",
 8080:"http-alt",
 8443:"https-alt"
}

link_tags = [
 "a",
 "iframe",
 "embed",
 "img",
 "script"
]

with open("subdomains.txt", "rb") as file:
 subs_list = file.read().decode(errors="ignore").splitlines()
 
with open("files.txt", "rb") as file:
 files_list = file.read().decode(errors="ignore").splitlines()
 
with open("extensions.txt", "rb") as file:
 extensions_list = file.read().decode(errors="ignore").splitlines()

headers_request = {
 "User-Agent":"Mozilla/5.0"
}

def scrape_content(url_base, r_text):
 soup = BeautifulSoup(r_text, "html.parser")
 links_full = []
 for link_tag in link_tags:
  for link in soup.find_all(link_tag):
   if link.has_attr("href"):
    links_full.append(link["href"])
   elif link.has_attr("src"):
    links_full.append(link["src"])
 for link in links_full:
  link = urljoin(url_base, link)
  root_base = "/".join(url_base.split("/")[:-1])
  if not root_base in link:
   continue
  print("Scraped link: {}".format(link))

def enum_files(url_current):
 for file in files_list:
  for extension in extensions_list:
   try:
    url_enum = urljoin(url_current, "{}{}".format(file, extension))
    r = requests.get(url=url_enum, timeout=5, verify=False, headers=headers_request, stream=True)
    if r.status_code == 200:
     print("Found file on {} -> {} and will now scrape it".format(url_current, url_enum))
     scrape_content(url_enum, r.text)
   except Exception as error:
    print(error)

def port_scan(full_domain):
 for port in commonports.keys():
  try:
   s = socket.socket()
   s.settimeout(1)
   s.connect((full_domain, port))
   print("Port open on {}: {} - {}".format(full_domain, port, commonports[port]))  
   if commonports[port].startswith("http"):
    url_current = "https://{}:{}/".format(full_domain, port) if commonports[port].startswith("https") else "http://{}:{}".format(full_domain, port)
    print("Enumerating files on http(s) endpoint: {}".format(url_current))
    enum_files(url_current)
  except Exception as error:
   pass

def try_resolve_sub(full_domain):
 global subdomains
 try:
  resolver = dns.resolver.Resolver()
  resolver.timeout = 1
  resolver.lifetime = 1
  resolved = resolver.query(full_domain, "A")
  print("Found subdomain: {}".format(full_domain))
  print("Port scanning: {}".format(full_domain))
  port_scan(full_domain)
 except Exception as error:
  pass

def locate_subdomains(domain_start):
 while len(subs_list):
  with threading.Lock():
   subdomain = subs_list.pop(0)
  full_domain = "{}.{}".format(subdomain, domain_start)
  try_resolve_sub(full_domain) 

if __name__ == "__main__":
 if len(sys.argv) < 2:
  print("Enter the starting domain (example.com)")
  sys.exit(0)
 domain_start = sys.argv[1]
 subdomains = []
 threads = []
 print("Finding subdomains...")
 for i in range(100):
  t=threading.Thread(target=locate_subdomains, args=(domain_start,))
  t.start()
  threads.append(t)
 for t in threads:
  t.join()
  
 
 