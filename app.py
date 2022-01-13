from flask import Flask, render_template, request
import pickle
import numpy as np

from urllib.parse import urlparse,urlencode
import ipaddress
import re
import pandas as pd
from bs4 import BeautifulSoup
import numpy as np



def getDomain(url):  
  domain = urlparse(url).netloc
  if re.match(r"^www.",domain):
	  domain = domain.replace("www.","")
  return domain



# 2.Checks for IP address in URL (Have_IP)
import ipaddress
def haveIP(url):
  try:
    ipaddress.ip_address(url)
    ip = 1
  except:
    ip = 0
  return ip



def haveAtSign(url):
  if "@" in url:
    at = 1    
  else:
    at = 0    
  return at



def urlLength(url): 
  if len(url) < 54: 
    return 0
  else: 
    return 1

short_url_services =  r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

def usesTinyUrl(url):      
  temp = re.search(short_url_services, url)
  if(temp):
    return 1
  else: 
    return 0

def haveHyphen(url): 
  if '-' in urlparse(url).netloc:
    return 1            # phishing
  else:
    return 0            # legitimate



import tldextract
def multiSubDomain(url):   
  x = tldextract.extract(url)
  

def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1
    else:
      return 0
  else:
    return 0

def httpDomain(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1
  else:
    return 0


import requests
#not working correctly





#finding the domani registration date from the url
import whois 
from datetime import datetime
from dateutil.relativedelta import relativedelta
def domainRegLength(url):
  try: 
    temp = whois.whois(url)      
    #print(datetime.today(), ' credate ', temp.creation_date[0])  
    return relativedelta(datetime.today(), temp.creation_date[0]).years
  except: 
    return 0

#checking the existense of hidden http/https
def hiddenhttps(url): 
  domain = urlparse(url).netloc
  if 'https' in domain: 
    return 1
  else: 
    return 0

def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth

import zipfile
import requests



import csv
with open('top-1m.csv') as f:
    reader = csv.reader(f)
    alexa = list(reader)

def web_traffic(url):
  domain = getDomain(url)
  try:
    rank = [i for i, v in enumerate(alexa) if v[1] == domain][0] + 1
  except:
    return 0
  if rank <100000:
    return 1
  else:
    return 0

def domainAge(domain_name):
  creation_date = domain_name.creation_date
  expiration_date = domain_name.expiration_date
  if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
    try:
      creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if ((expiration_date is None) or (creation_date is None)):
      return 1
  elif ((type(expiration_date) is list) or (type(creation_date) is list)):
      return 1
  else:
    ageofdomain = abs((expiration_date - creation_date).days)
    if ((ageofdomain/30) < 6):
      age = 1
    else:
      age = 0
  return age

def domainEnd(domain_name):
  expiration_date = domain_name.expiration_date
  if isinstance(expiration_date,str):
    try:
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if (expiration_date is None):
      return 1
  elif (type(expiration_date) is list):
      return 1
  else:
    today = datetime.now()
    end = abs((expiration_date - today).days)
    if ((end/30) < 6):
      end = 0
    else:
      end = 1
  return end

def iframe(response):
    if response == "":
        return 1
    else:           
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        else:
            return 1

def mouseOver(response): 
  if response == "" :
    return 1
  else:    
    if re.findall("<script>.+onmouseover.+</script>", response.text):
      return 1
    else:
      return 0

def rightClick(response):
  if response == "":
    return 1
  else:    
    if re.findall(r"event.button ?== ?2", response.text):
      return 0
    else:
      return 1

def forwarding(response):
  if response == "":
    return 1
  else:    
    if len(response.history) <= 2:
      return 0
    else:
      return 1

def featureExtraction(url):
  feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
                      'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record',
                      'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards', 'Label']
  features = []
  #Address bar based features  are working correctly    
  
  features.append(haveIP(url))
  features.append(haveAtSign(url))
  features.append(urlLength(url))
  features.append(getDepth(url))
  features.append(redirection(url))
  features.append(hiddenhttps(url))
  features.append(usesTinyUrl(url))
  features.append(haveHyphen(url))
  
  #Domain based features  working correctly
  dns = 0
  try:
    domain_name = whois.whois(urlparse(url).netloc)
  except:
    dns = 1

  features.append(dns)
  features.append(web_traffic(url))
  features.append(1 if dns == 1 else domainAge(domain_name))
  features.append(1 if dns == 1 else domainEnd(domain_name))
  
  # HTML & Javascript based features working correctly
  temp = ['1']*4


  try:   
    response = requests.get(url, timeout=5 )        
    print('HTTP response code: ', response.status_code)
    if response.status_code == 200:       
      features.append(iframe(response))      
      features.append(mouseOver(response))    
      features.append(rightClick(response))    
      features.append(forwarding(response))             
    else: 
      print('Not reachable - ', url)
      features.extend(temp)
  except:     
    print('Timeout - ', url)
    features.extend(temp)
  return features




model = pickle.load(open('PhishWebDetModel.pkl', 'rb'))

app = Flask(__name__)



@app.route('/')
def man():
    return render_template('home.html')


@app.route('/predict', methods=['POST'])
def home():
  url = request.form["a"]
  arr = []
  arr.append(featureExtraction(url))
  feature_names = ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards']
  Finalarr = pd.DataFrame(arr, columns= feature_names)
  pred = model.predict(arr)
  return render_template('after.html', predictedvalue=pred)


if __name__ == "__main__":
    app.run(debug=True)















