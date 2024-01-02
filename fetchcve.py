import requests
import json
import re
from datetime import datetime, timedelta

# If you have colorama installed
COLOURFUN = False
try:
    from colorama import Fore, Style
    COLOURFUN = True
except: 
    pass
    
# PANDAS on PC or Std print on Phone
PANDABEAR = False
try:
    import pandas as pd
    PANDABEAR = True
except:
    pass

def check_string(desc):
    xss_keywords = [
        r'\bXSS\b', 
        r'Cross[- ]?site script'
    ]
    sqli_keywords = [
        r'\bSQLi?\b'
    ]
    ssrf_keywords = [
        r'ssrf',
        r'server[- ]?side request for'
    ]
    open_redirect_keywords = [
        r'Open[- ]?redirect'
    ]
    csrf_keywords = [
        r'Cross[- ]?site request for'
    ]
    #rce_keywords = [
    #    r'Remote[- ]?Code[- ]?Execution'
    #]
    xss_pattern = re.compile('|'.join(xss_keywords), re.IGNORECASE)
    sqli_pattern = re.compile('|'.join(sqli_keywords), re.IGNORECASE)
    ssrf_pattern = re.compile('|'.join(ssrf_keywords), re.IGNORECASE)
    open_redirect_pattern = re.compile('|'.join(open_redirect_keywords), re.IGNORECASE)
    csrf_pattern = re.compile('|'.join(csrf_keywords), re.IGNORECASE)
    #rce_pattern = re.compile('|'.join(rce_keywords), re.IGNORECASE)
    
    if xss_pattern.search(desc):
        return 'XSS'
    elif sqli_pattern.search(desc):
        return 'SQLi'
    elif ssrf_pattern.search(desc):
        return 'SSRF'
    elif open_redirect_pattern.search(desc):
        return 'Redirect'
    elif csrf_pattern.search(desc):
        return 'CSRF'
    #elif rce_pattern.search(desc):
    #    return 'RCE'
    else:
        return None

# Query nist.gov with specified start and end times
def get_daily_cve():
    yesterday = (datetime.today() - timedelta(days=3)).strftime('%Y-%m-%d')

    start_date_time = yesterday+"T00:00:00.000%2B01:00"
    end_date_time = yesterday+"T23:59:59.000%2B01:00"
    
    cve_data = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=2000&lastModStartDate={start_date_time}&lastModEndDate={end_date_time}")
    
    json_data = json.loads(cve_data.content)
    return json_data
    
# See if any of the CVEs involve: sqli, xss, or ssrf. Add more going forward.
def get_main_bugs(json_data):
    return_data = []
    for key in json_data:
        if key in ['vulnerabilities', 'Vulnerabilities']:
            for cve in json_data[key]:
                cvedata = cve['cve']
                for desc in cvedata['descriptions']:
                    # skip all languages other than English
                    if desc['lang'] != 'en':
                        pass
                    else:
                        description = desc['value']
                        vuln_type = check_string(description)
                        if vuln_type != None:
                            if 'metrics' in cvedata and 'cvssMetricV31' in cvedata['metrics']:
                                cve_id = cvedata['id']
                                cvss_score = cvedata['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']  
                                if (cvss_score in ['MEDIUM', 'HIGH', 'CRITICAL']):
                                    return_data.append({"CVE": cve_id, "TYPE":vuln_type, "CVSS": cvss_score, "DESCRIPTION":description.strip('\n')})
                        else:
                            break;
    return return_data
    
def main():
    rd = get_main_bugs(get_daily_cve())
   
    if PANDABEAR == True:
        # Print table using pandas
        df = pd.DataFrame(rd)
        pd.set_option('display.max_colwidth', 80)
        
        #df_sorted = df.sort_values(by='CVSS', ascending=True)
        print(df)
        exit(0)      
    else:
    
    # Standard print to screen          
        for l in rd:
            if COLOURFUN == True:
                if l['CVSS'] == 'CRITICAL':
                    print(f"CVE:\t{Fore.GREEN}{Style.BRIGHT}{l['CVE']}{Style.RESET_ALL}\nTYPE:\t{Fore.CYAN}{l['TYPE']}{Style.RESET_ALL}\nCVSS\t{Fore.RED}{Style.BRIGHT}{l['CVSS']}{Style.RESET_ALL}\nDescription: {l['DESCRIPTION']}\n")
                elif l['CVSS'] == 'HIGH':
                    print(f"CVE:\t{Fore.GREEN}{Style.BRIGHT}{l['CVE']}{Style.RESET_ALL}\nTYPE:\t{Fore.CYAN}{l['TYPE']}{Style.RESET_ALL}\nCVSS\t{Fore.RED}{l['CVSS']}{Style.RESET_ALL}\nDescription: {l['DESCRIPTION']}\n")
                elif l['CVSS'] == 'MEDIUM':
                    print(f"CVE:\t{Fore.GREEN}{Style.BRIGHT}{l['CVE']}{Style.RESET_ALL}\nTYPE:\t{Fore.CYAN}{l['TYPE']}{Style.RESET_ALL}\nCVSS\t{Fore.YELLOW}{l['CVSS']}{Style.RESET_ALL}\nDescription: {l['DESCRIPTION']}\n")
                    
            else:
                print(f"CVE:\t{l['CVE']}\nTYPE:\t{l['TYPE']}\nCVSS\t{l['CVSS']}\nDescription: {l['DESCRIPTION']}\n") 

if __name__ == '__main__':
    main()
