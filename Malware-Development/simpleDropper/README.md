# Simple Dropper

This simple dropper would reach out to the malicious domain we passed as a parameter to the URLDownloadToFile function and save it in the directory that we specified. 

## What is a dropper?

A dropper is a small program designed to deliver and execute a secondary payload (e.g., malware or a testing binary) on a target system. This a simplified example and real world malware involves far more sophisticated strategies and evasion techniques. 

Documentation to the two functions used:

[URLDownToFile](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123(v=vs.85))

[ShellExecute](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutea)

