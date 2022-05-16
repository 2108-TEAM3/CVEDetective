#!/usr/bin/env python3

import requests
#import json
import csv
import nmap
import pyfiglet
import ipaddress
import magic
import sys
import re
import urllib.parse

#PRINT FORMAT
class bcolors:
  MEDIUM = '\033[92m' #GREEN
  HIGH = '\033[93m' #YELLOW
  CRITICAL = '\033[31m' #RED
  LOW = '\033[1;37m' # WHITE
  CPE = '\033[0;36m' #CYAN
  RESET = '\033[0m' #RESET COLOR
  UL = '\033[4m' #Underline
  CPEH = '\u001b[34m'

#INPUT
bannerName = pyfiglet.figlet_format('CVE Detective')
print(bannerName)

#FINAL LIST_CPE STRINGS
inputFinal = []

#_____________________________________________________
#VALIDATION FUNCTIONS

#VALIDATION_MENU_INPUT
def inputValCharTypeofInput(inputFromMenu):
  inputGood = True
  allowed = ['1','2','3','4']
  if any(x not in allowed for x in inputFromMenu):
    inputGood = False
    #disable "test" mode - Tony
#    if inputFromMenu == 'test':
#        inputGood = True
  #offer option to quit - Tony
  if inputFromMenu == 'q':
    sys.exit()
  
  return inputGood

#VALIDATION_CPE
def inputValCharManual(inputCPEs):
  inputGood = True

  #addressed by re.match() below and .rstrip(",") when assigning CPEsString - Tony
  #Checks for characters not found in CPEs
#  allowed = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','1','2','3','4','5','6','7','8','9','0',',','*',' ',':','.','/','_']

#  if any(x not in allowed for x in inputCPEs):
#    inputGood = False
#    print("Invalid input. Forbidden characters.")

#  if (inputCPEs[-1] == ' ' or inputCPEs[-1] == ','):
#    inputGood = False
#    print("Error - do not end with a space or comma!")

  #alternative to character check via re - Tony
  if any(not re.match("[a-z0-9_*,.:/]", char) for char in inputCPEs):
    inputGood = False
    print("Error - invalid characters detected.")
#  for char in inputCPEs:
#    if not re.match("[a-z0-9_*,.:/]", char):
#      print("Error - invalid characters detected!")
#      inputGood = False
#      break

  return inputGood

#VALIDATON_FILE_PATH_NAME
def inputValCharFile(nameOrPath): #needs work
  inputGood = True

  filetype = magic.from_file(file, mime=True)

  if not(filetype == 'text/plain'):
    inputGood = False

  return inputGood

#__________________________________________________________
#MENU_USER

while True:
  TypeofInput = input (
    """Please select from the following:
  1) To enter CPE value
  2) To load file with CPE values
  3) To run an nmap scan
Enter number, or 'q' to quit: """)
  if not (inputValCharTypeofInput(TypeofInput)):
    print("Invalid input - please try again.")
    continue
  else:
    break

#__________________________________________________________
#1) MANUAL_CPE(s)
if TypeofInput == "1":

  #Checks for valid input. Repeats check until valid input is entered.
  while True:
    #sanitizes input with trailing comma (allowed char otherwise) - Tony
    CPEsString =  input("Enter CPE(s) separated by a comma \",\" or 'q' to quit:\n").rstrip(",")
    if not (inputValCharManual(CPEsString)):
        continue
    #offer option to quit - Tony
    elif CPEsString == 'q':
      sys.exit()
    else:
        break

    #Check for number of CPEs entered, extract CPEs from terminal input_string
  if len(CPEsString) > 0:
    NumofCPEs = CPEsString.count(",") + 1
    #One CPE
    if NumofCPEs == 1:
      inputFinal.append(CPEsString)
    #More than one CPE
    elif NumofCPEs > 1:
      if ", " in CPEsString:
        inputFinal = CPEsString.split(", ")
      else:
        inputFinal = CPEsString.split(",")

#_______________________________________________________
#2) FILE_LIST_CPE(s)
if TypeofInput == "2":

  #File path validation
  while True:
    try:
      file = input("Enter full path or file name:\n")
      if (inputValCharFile(file)) != FileNotFoundError:
        break
      #offer option to quit - Tony
      if file == 'q':
        sys.exit()
    except FileNotFoundError:
      print("Invalid path or file name - please try again, or 'q' to quit")

  #Read file and validation
  with open(file) as f:
    lines = f.readlines()
    #accommodate CPEs either separated by comma, or in separate lines
    for item in lines:
      if "," in item:
#        print(item.rstrip("\n").rstrip(","))
        item_list = item.rstrip("\n").rstrip(",").split(",")
#        print(item_list)
        for i in range(len(item_list)):
          item = item_list[i].rstrip("\n")
#          print(item)
          if inputValCharManual(item) == False:
            print(item_list[i] + " appears to be invalid - please check your data.")
            sys.exit()
          #duplicate check - Tony
          if item not in inputFinal:
                inputFinal.append(item.strip())
      else:
        item = item.rstrip("\n")
        if inputValCharManual(item) == False:
          print(item + " appears to be invalid - please check your data.")
          sys.exit()
        #duplicate check - Tony
        if item not in inputFinal:
          inputFinal.append(item.strip())
#  print(len(inputFinal))

#_______________________________________________________
#3) NMAP SCAN
if TypeofInput == "3":

  #IP address input validation
  while True:
    try:
      ip_addr = input("Please enter target IP address: \n")
      #offer option to quit - Tony
      if ip_addr == 'q':
        sys.exit()
      if (ipaddress.ip_address(ip_addr)) != ValueError:
        break
    except ValueError:
      print("Invalid IP address - please try again, or 'q' to quit")
      continue

  #Nmap Scan
  scanner = nmap.PortScanner()

  #ip_addr = input("Please enter the IP address you would like to scan:\n")
  ports = '1-10000'

  #print(scanner.scan(ip_addr, ports, '-sV'))
  output = scanner.scan(ip_addr, ports, '-sV')
  #print(output['scan']['192.168.56.102']['tcp'])
  inner_dict = output['scan'][ip_addr]['tcp']
  for port_key in inner_dict:
    cpe = inner_dict[port_key]['cpe']
    #print(inner_dict[port_key]['cpe'])
    if cpe not in inputFinal:
      inputFinal.append(cpe)

#______________________________________________________
#4) EASTER EGG
if TypeofInput == "4":
    print("To be continued...")



dict_CPE = {}
dict_noCVE = {'id':'No CVEs found','cvss':'N/A','summary':'N/A','references':'N/A'}
dict_error = {'id':'No CVEs found, try a more specific CPE','cvss':'N/A','summary':'N/A','references':'N/A'}

#for loop to add each CPE as key to dict_CPE, list_CVE (server response) as value, dict_CVE_attributes ('id', 'CVSS' etc.) as sub-dictionaries
for i in range(len(inputFinal)):
  response = requests.get("https://vuln.sentnl.io/api/cvefor/" + inputFinal[i])
#  print(response.status_code)
  if response.status_code == 200 or response.status_code == 404:
    data = response.json()
#  print(data)
    dict_CPE[inputFinal[i]] = data
#  print(dict_CPE)
  else:
#    print(bcolors.FAIL + inputFinal[i] + bcolors.RESET + ": error, please check CPE")
    #update dict_CPE with unresponsive CPE queries
    dict_CPE[inputFinal[i]] = [dict_error]
    continue

#iterate through CPE:CVE_list dictionary ("CPE_input":"server_response_list")
for key_CPE in dict_CPE:
#check for CPE w/o CVE
  if type(dict_CPE[key_CPE]) == dict and "No cves found" in dict_CPE[key_CPE].get('message'):
#    print(dict_CPE[key_CPE])
#update server response (dictionary) to list_dict_noCVE
    dict_CPE[key_CPE].update(dict_noCVE)
    dict_CPE[key_CPE] = [dict_CPE[key_CPE]]
#    print(dict_CPE)

#CSV writer_header
header = ["CPE","CVE","CVSS","Summary","References"]
with open('CVE_output.csv', 'w', encoding='UTF8') as f:
  writer = csv.writer(f)
  writer.writerow(header)

#iterate through CPE:CVE_list dictionary ("CPE_input":"server_response_list")
for key_CPE in dict_CPE:
  print("-" * 70 + '\n')
#  print(dict_CPE[key_CPE][0])

  #add count of CVE(s) to CPE print
  if "No CVEs found" in dict_CPE[key_CPE][0].get('id'):
    print(bcolors.CPEH + key_CPE + bcolors.RESET + " (" + str(0) + ")" + "\n")
    
  else:
    print(bcolors.CPEH + key_CPE + bcolors.RESET + " (" + str(len(dict_CPE[key_CPE])) + ")" + "\n")

  #sort list of dict_CVE by CVSS:value, id:value per CPE
  dict_CPE_sorted = sorted(dict_CPE[key_CPE], key=lambda x: (x['cvss'], x['id']), reverse=True)
#  print(dict_CPE_sorted)

  #iterate through list_dict_CVE per CPE to print
  for dict_CVE in dict_CPE_sorted:
#    print(dict_CVE)
    print("| " + str(dict_CVE['id']) + " ", end="")

    #check for CPE without CVE
    if type(dict_CVE['cvss']) == str:
      print("| CVSS: " + str(dict_CVE['cvss']) + bcolors.LOW + " [?]" + bcolors.RESET + '\n')

    elif dict_CVE['cvss'] <= 3.9:
      print("| CVSS: " + str(dict_CVE['cvss']) + bcolors.LOW + " [LOW]" + bcolors.RESET + '\n')
  
    elif dict_CVE['cvss'] >= 4.0 and dict_CVE['cvss'] <= 6.9:
      print("| CVSS: " + str(dict_CVE['cvss']) + bcolors.MEDIUM + " [MEDIUM]"+bcolors.RESET + '\n')
  
    elif dict_CVE['cvss'] >= 7.0 and dict_CVE['cvss'] <= 8.9:
      print("| CVSS: " + str(dict_CVE['cvss']) + bcolors.HIGH + " [HIGH]"+bcolors.RESET + '\n')
      
    elif dict_CVE['cvss'] >= 9.0:
      print("| CVSS: " + str(dict_CVE["cvss"]) + bcolors.CRITICAL + " [CRITICAL]"+bcolors.RESET + '\n')
      
#      print("| Summary | " + str(dict_CVE['summary'][:100] + "\n")

    #check for CPE without CVE
    if type(dict_CVE['cvss']) == str:
      #check for CPE version
      if "/" in key_CPE:
        CPEv = 2.2
      else:
        CPEv = 2.3
      #NIST URL encoding for CPE search 
      print(bcolors.UL+"NIST URL: " + "https://nvd.nist.gov/products/cpe/search/results?namingFormat=" + str(CPEv) + "&keyword=" + urllib.parse.quote(key_CPE, safe='') + bcolors.RESET + '\n')
  
    else:
      #NIST URL encoding for CVE detail
      print(bcolors.UL+"NIST URL: " + "https://nvd.nist.gov/vuln/detail/" + str(dict_CVE['id']) + bcolors.RESET + '\n')

    #CSV writer_data
    if "No CVEs found" in dict_CPE[key_CPE][0].get('id'):
      data = [
        key_CPE,
        str(dict_CVE['id']),
        str(dict_CVE['cvss']),
        str(dict_CVE['summary']),
        str("https://nvd.nist.gov/products/cpe/search/results?namingFormat=" + str(CPEv) + "&keyword=" + urllib.parse.quote(key_CPE, safe=''))
        ]
    else:
      data = [
        key_CPE,
        str(dict_CVE['id']),
        str(dict_CVE['cvss']),
        str(dict_CVE['summary']),
        str("https://nvd.nist.gov/vuln/detail/" + str(dict_CVE['id']))
#        str(dict_CVE['references'])
        ]
#    print(data)
    with open('CVE_output.csv', 'a', encoding='UTF8') as f:
      writer = csv.writer(f)
      writer.writerow(data)

print("-" * 70)