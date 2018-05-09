# Python-IOC-Scanner
Scans text for domain name/IP address IOCs and outputs to spreadsheet!

What it does:
1. Scans "message.txt" in the same directory for IP/domain name IOCs.
2. Determines levels of confidence for domain name IOCs ("Definite" domain name if has TLD, "possible" if not recognized TLD).
3. Excludes domain names that are subdomains/matches to domains in the whitelist.
4. Outputs detected IOCs to "IOCs.csv" in the following format: 'date, description, type (domain/IP), ioc'.

How to use it:
1. Place it in any directory along with "message.txt" (your text to scan), "whitelist.txt", and "IOCs.csv". The included whitelist and message are just proof-of-concept samples, replace these with your own.
2. Run the python script.

Optionally, import the Visual Basic macro in "VisualBasicMacro.txt" to Outlook to automatically output any selected email to text and run the script! (Note: if you do this, you must place the script and .txt files under C:\Temp, or edit the macro to your liking)

Notes:
- Ignores most data that looks like domain names that are actually part of email addresses or filenames.
- IOC data that comes in in weird formats (like in a table) in an email may not be detected.
- IP address whitelisting not implemented yet.
