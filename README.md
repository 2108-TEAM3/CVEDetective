# CVE Detective #
![Image](https://security.virginia.edu/sites/security.virginia.edu/files/e%20a%20hack%20detective..jpg)

## Overview  ##
CVE Detective is a Python script that will help to automate finding all (if any) Common Vulnerablility and Exposures (CVEs) associated to any Common Platform Enumeration (CPEs) of a software, application, or Operating System.  From the Shell terminal, you may input a single CPE, a list of CPEs (comma separated), or a upload a .txt file of CPEs.  This program also includes the functionality to perform an NMap scan to find any CPE of a target machine and output the associated CVEs found on the target machine.

## Features
  * Utilizes vuln.sentnl.io's API (HTTP REST) to query the CPE input(s) and output CVE information:
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
>     
>      Base Score | Criticality Rating | Color
>      ---------- | ------------------ | ------
>      9.0 - 10.0 |      Critical      | Red
>       7.0 - 8.9 |        High        | Orange
>       4.0 - 6.9 |       Medium       | Cyan
>       0.1 - 3.9 |        Low         | White
>   
> 2. The order of CPEs will follow the same order that is input into the terminal or the text file to be uploaded.
> 3. A CSV file containing similar information to the output in the terminal will be saved in the same folder where the CVE-Detective script is ran from.


### Option 1: Inputting a Single CPE or Multiple CPEs on the Shell
#
### Input Format
CPEs may be entered as a single CPE or multiple CPEs. Multiple CPEs must be separated by a comma. 


#### &ensp;Examples:
```
cpe:/a:apache:activemq_artemis:2.6.3
```
```
cpe:/a:apache:activemq_artemis:2.6.3, cpe:2.3:a:apache:activemq:5.14.0:*:*:*:*:*:*:*, cpe:2.3:a:apache:accumulo:1.4.1:*:*:*:*:*:*:*
```

### Potential Errors
#### &ensp;Trailing spaces or commas
When a single CPE or the last CPE in a list of multiple CPEs is trailed by a space or comma, an error message will be displayed and you will be asked to enter CPE(s) again.

![image](https://user-images.githubusercontent.com/100049886/155851250-aecdfb18-8368-4c89-b4bb-d2c6c9559d65.png)

#### &ensp;Invalid Characters
Invalid characters will cause the program to display an invalid input message and ask the user to enter CPE(s) again. 
#### &ensp;Example:
```
$#^&
```

### Option 2: Uploading a Text File Containing CPEs into the Script
#
### Input Format for File Names and File Paths
File paths must be entered as full files paths while file names can be used when the referenced file is in the same directory where the program is stored.

### Potential Errors
#### &ensp;File paths and names that do not exist
When an invalid file name or path is entered, you will have the option to try again.

#### &ensp;Examples:
![image](https://user-images.githubusercontent.com/100049886/155851703-f7b25c61-cc0f-4d83-bb51-1b96dd879c47.png)

![image](https://user-images.githubusercontent.com/100049886/155851715-f4c76dbc-799c-44af-991b-214c242ab8fc.png)


### Option 3: Utilizing the Integrated NMap Scan 
#
This option will perform a nmap (-SV) scan on a target machine and return known CVEs associated with the CPEs found, given a valid IP address.
> Note
> 1. Input of a valid IP address will be checked and, if invalid, user will be prompted to re-enter (CTRL+C to quit).
> 2. Loading times may vary depending on the CPEs found, longer if more general CPEs are encountered.






