# CVE Detective #
![Image](https://security.virginia.edu/sites/security.virginia.edu/files/e%20a%20hack%20detective..jpg)

## Overview  ##
This python script will help to automate finding all (if any) Common Vulnerablility and Exposures (CVEs) associated to any Common Platform Enumeration (CPEs) of a software, application, or Operating System.  You may input a single CPE, a list of CPEs separated by commas, or a text file of CPEs.  This program also has the functionality to use an NMap scan to find any CPEs of a target machine and output the CVEs associated with all CPEs found on the target machine.

## Features
  * Utilizes vuln.sentnl.io's REST API to query the CPE input(s) and output CVE information
    * Output includes the CVE ID, CVSS score, and external link to the NIST's National Vulnerability Database (NVD) to provide a more thorough summary and suggestions for mitigation.
    * For each CPE, their CVE output on the shell is sorted based on their CVSS scores from highest criticality/priority to the lowest.
    * The script also saves the output into a CSV file in the same folder the script is run in.
  * Includes 3 options for retrieving CVE information:
    * You may upload a single CPE, or multiple CPEs separated by commas on the shell itself
    * You may upload a text file containing a single, or multiple CPEs.
    * You may use an NMap scan that is integrated with this script to automate finding the CPEs of a target machine and get the information of all CVEs (if any) of the CPEs found by that NMap scan. 

## Installation Pre-requisites
This script uses several libraries in which 2 are not included in Python already and will need to be installed by typing the below commands in your terminal:
``` 
pip install -U python-nmap
```
```
pip install pyfiglet
```

## Required Format for Each Input Option
No matter which option you decides to choose, you should follow a strict format as described below:

### CPE Format
This script is able to accept CPEs in both versions 2.2 and 2.3. Examples of both are shown below.
#### &ensp;Examples:
```
cpe:/a:apache:activemq_artemis:2.6.3
```
```
cpe:2.3:a:apache:accumulo:1.7.0:::::::
```

### Option 1: Inputting a Single CPE or Multiple CPEs on the Shell
#
stuff
### Option 2: Uploading a Text File Containing CPEs into the Script
#
to put
### Option 3: Utilizing the Integrated NMap Scan 
#
later


* Input a single CPE or multiple CPEs into the shell
* Upload a text file containing a single CPE or multiple CPEs
* Provide an IP address of a target machine. (This option does not require that the user has a number of CPEs to input prior to running the script)

#### Minimum Viable Project Outcomes ####
  * We will be able to take a user's single CPE input and query it against either the vulner's or vuln's databse and get all the CVE's associated with said CPE
  
####  Stretch Goals #####
  * Our script will be able to take different forms of user input such as:
    * Multiple CPE's separated by commas
    * A file (text file or possibly an Excel file) of CPE's
  * Our script will be able to automate finding the CPE's of a given target machine using NMap through Python
  * Our script will be able to save the output (CVE's, description of the CVE, etc.) into an file (Excel file or text file)
