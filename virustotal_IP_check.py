######################################################################################################################
#######################                  Script that checks if a given IP is                   #######################                  
#######################                  found to be malicious on VirusTotal                   #######################
#######################                   Sourced from tutorials, modified by                  #######################
#######################                      gh caridinL6                                      #######################
#######################      https://github.com/caridinL6/VirusTotal-IP-Address-Check.git      #######################
######################################################################################################################

import requests
from bs4 import BeautifulSoup
import ipaddress
import sys


## Gather user input for the malicious IP Check
## To test if malicious/suspicious IP testing is working use 1.1.1.1
print("Please enter the IPv4 Address to check: ")
ipv4_add = input()

def validate_ip_address(ip_string):
    try:
        ipv4_object = ipaddress.ip_address(ip_string)
        print("The IP address %s is a correctly formatted IP Address." % ipv4_object)
    except ValueError:
        print("The given IP address, %s, is not a valid IP address." % ip_string)
        sys.exit()

validate_ip_address(ipv4_add)

# Key must be provided by the user, DO NOT hardcode your API key here for "ease" unless you want it to get used by someone else :-P
print("Please enter your VirusTotal API key: ")
vt_api_key = input()

virus_total_request = requests.get("https://www.virustotal.com/api/v3/ip_addresses/%s" % ipv4_add, headers={'User-agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0', 'x-apikey': '%s' % vt_api_key}).json()

# From the virus_total_request, we are taking the "data">"attributes">"last_analysis results" object and storing it in the variable data_output in order to provide a final stats on the ip.... the last analysis results object provides category, engine_name, method, result as output.
# Reference: https://developers.virustotal.com/reference/ip-object
data_output = virus_total_request["data"]["attributes"]["last_analysis_results"]


# Setting up two variables to count the # of engines and detections found against the user provided IP address by Virus Total. Note that engines counts all engines and detections counts every detection. 
total_engines = 0
total_detections = 0

# When an IP is found to be malicious/suspicious these two variables store, in a list, the results from the engine and the detection engine name
result_from_engine = []
eng_name = []

# This variable stores the # of engines that have rated this IP address as benign or "not malicious"
count_benign = 0

for i in data_output: # iterates through all the analysis results from all the different engines 
    total_engines = 1 + total_engines # ticks the total engines calculator up 1
    if data_output[i]["category"] == "malicious" or data_output[i]["category"] == "suspicious": # 
        result_engine.append(data_output[i]["result"]) # appends the result engine that is found to be malicious
        eng_name.append(data_output[i]["engine_name"]) # appends the engine name of the engine that found this to be malicious or suspicious
        total_detections = 1 + total_detections

# Provides categorical details of why a given malicious or suspicious IP Address was rated as such. Possible  The first variable stores a list of the malicious category and appends the finding to the list
malicious_category = []
for finding in result_engine:
    if finding not in malicious_category:
        malicious_category.append(finding)

if total_detections > 0:
    print("The given IP address, %s, was rated as " % ipv4_add + str(result_engine)[1:-1] + " on " + str(total_detections) + " engines out of " + str(total_engines) + " engines. The engines which reported this are: " + str(eng_name)[1:-1] + " respectively.")
else:
    print("The given IP address %s " % ipv4_add + "was found to be non-malicious or suspicious from all " + str(total_engines) + "detection engines tested.")