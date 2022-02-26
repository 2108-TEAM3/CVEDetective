# CVE Detective #
![Image](https://security.virginia.edu/sites/security.virginia.edu/files/e%20a%20hack%20detective..jpg)

## Overview  ##
CVE Detective is a Python script that will help to automate finding all (if any) Common Vulnerablility and Exposures (CVEs) associated to any Common Platform Enumeration (CPEs) of a software, application, or Operating System.  From the Shell terminal, you may input a single CPE, a list of CPEs separated by commas, or a upload text file of CPEs.  This program also includes the functionality to perform an NMap scan to find any CPEs of a target machine and output the CVEs associated with all CPEs found on the target machine.

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

## CVE-Detective Menu
![image](https://user-images.githubusercontent.com/100049886/155829840-ff72683d-e913-4271-8680-38ca57949608.png)

## Required Format and Expected Output
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

### Results
If there are no errors, you can expect an output like this:
![image](https://user-images.githubusercontent.com/100049886/155830179-7d390c66-ddaa-4b9a-b027-8a89f9121a0a.png)

For each CPE, you can expect the output of CVE-Detective to include:
* CVE-IDs 
* the CVSS Score of that CVE and its criticality rating
* an link to the NIST's Vulernability Database for that CVE
  * this link will provide more detail about that CVE and suggestions for remediation/mitigation 

> Note
> 1. If a single CPE has multiple CVEs, they will be displayed in order by CVSS Score and their criticality rating based on that score.
>     1. The criticality rating is based on the most current CVSS version (CVSS v3.1) with a color associated to each criticality score. Each score can be broken down as follows:
>     Base Score | Criticality Rating | Color
>     ---------- | ------------------ | ------
>     
>   
> 2. The order of CPEs will follow the same order that is input into the terminal or the text file to be uploaded.


### Option 1: Inputting a Single CPE or Multiple CPEs on the Shell
#
stuff
### Option 2: Uploading a Text File Containing CPEs into the Script
#
to put
### Option 3: Utilizing the Integrated NMap Scan 
#
later

