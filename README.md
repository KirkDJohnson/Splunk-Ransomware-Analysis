<h1>Splunk Ransomware Log Analysis</h1>



<h2>Description</h2> 
In this lab, I was provided with a virtual machine on tryhack.com containing a Splunk instance with logs. My task was to investigate suspected ransomware activity. Upon narrowing down the time frame of the incident, I initially encountered a suspicious binary named OUTSTANDING_GUTTER[.]exe. However, I couldn't determine how it was installed on the host or identify any signs of malicious activity. Filtering for Sysmon event code 3 for network communications, I discovered that both the binary and PowerShell were establishing connections. Upon inspecting images spawned from PowerShell, I stumbled upon an encoded script. Decoding it revealed that it had disabled Windows Defender, downloaded the suspicious binary, and created a scheduled task running with system privileges. Continuing my investigation, I sought out clear outbound connections and identified a suspicious domain along with multiple IP addresses, but hit a dead end. Upon revisiting PowerShell activity, I found evidence of additional downloads and scripts. Analyzing one such script, script.ps1, and obtaining its hash, I uncovered that it was associated with the Blacksun ransomware. At this juncture, the evidence previously encountered confirmed that the ransomware had indeed created files and altered file extensions, encrypting data on the host machine.

<br />


<h2>Utilities Used</h2>

- <b>Splunk</b>
- <b>Virus Total</b> 

<h2>Environments Used </h2>

- <b>Windows 10 </b>

<h2>Lab Overview</h2>

<p align="center">
Scenario for the lab.<br/>
<img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/aa32b060-4d54-4fa5-9c7b-2ff69c134b91" height="80%" width="80%" alt="Splunk Log Analysis"/>
<br />
<br />
Now that we know the timeframe and the user effected I can better filter the logs most relevant to the incident, however, the index was not specified so used index=* shows all logs.<br/>
<img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/ef9cf24c-18af-447f-bfe3-aa494737bd31" height="80%" width="80%" alt="Splunk Log Analysis"/>
<br />
<br />
Since the scenario metnioned that it was downloaded, I filtered for Image to see if there were suspicious binaries apparent and there was a program OUTSTANDING_GUTTER[.]exe that was seemed worth investigating. I found the hash and uploaded it to virus total, however the result was begign. <br/>
<img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/fb02a704-96d7-4d31-b22f-21a35526b7ec" height="80%" width="80%" alt="Splunk Log Analysis"/>
  <img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/f3f48464-8b49-4201-9cd5-868bde984671" height="80%" width="80%" alt="Splunk Log Analysis"/>
  <img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/4b00a734-a57a-479a-806c-2cfa6692d8bc" height="80%" width="80%" alt="Splunk Log Analysis"/>
<br />
<br />
Filtering for it in the logs, and reversing the order to see the first instance of it on the host did not reveal how it was installed on the host so I will have to look elsewhere.<br/>
<img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/47d8ca12-b358-4ef0-8c29-08a4af6544d3" height="80%" width="80%" alt="Splunk Log Analysis"/>
<br />
<br />
Looking at Sysmon Event Code: 3 for to see if there were any TCP/UDP connections that could have downloaded the binary, I see OUTSTANDING_GUTTER[.]exe and Powershell which is also suspicious so I will investigate that further.<br/>
<img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/f60e60d4-4ded-482a-b2e7-4fc14d016393" height="80%" width="80%" alt="Splunk Log Analysis"/>
<img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/3b0ded2c-7d13-40d9-af21-87d4965d8573" height="80%" width="80%" alt="Splunk Log Analysis"/>
<br />
<br />
The powershell script is broken down is: powershell.exe runs the command, -exec bypass ignores the current execution policy and execute the script no matter what, the -enc means that the following command is encoded in Base64 format. With this knowledge I went to cyberchef to decode the Base64 script.<br/>
<img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/82fb080d-058a-4ce5-a275-a172bb169a4a" height="80%" width="80%" alt="Splunk Log Analysis"/>
<br />
<br />
The decoded powershell script reveals considerable information about the attack, firstly, it disabled windows defender with the -DisableRealtimeMonitoring $true and then used wget to download the malicious binary we found earlier into the /temp directory, created the binary as a scheduled task running as SYSTEM or elevated privliges. Part of the command that was decoded can be found when filtering for the binary and commandline. <br/>
  <img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/75e2f86c-38f1-4709-81bd-9e364c7ef676" height="80%" width="80%" alt="Splunk Log Analysis"/>
<br/>
<br/>
 It is now clear there is a malicious executable that was downloaded with powershell and set to run as a scheduled task as SYSTEM, however, it was likely that there was more to uncover such as a Command and Control Server or data exfiltration so I added filters to see if there was any suspicious outbound traffic and found a suspicious dns query at "hxxp[://]9030-181-215-214-32[.]ngrok[.]io"<br/>
<img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/a2e077c4-4c05-45e9-9b5f-951661e70c5a" height="80%" width="80%" alt="Splunk Log Analysis"/>
  <img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/cf419545-1e4e-49b1-84b6-1e22e0a9ec4e" height="80%" width="80%" alt="Splunk Log Analysis"/>
  <img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/4da981f6-dcef-4a08-95c7-3d98562904a6" height="80%" width="80%" alt="Splunk Log Analysis"/>
<br />
<br />
Knowing that the the attacker used powershell to downloaded different malicious payloads targeting to the /temp folder, further examination shows a file "script.ps1"<br/>
<img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/7d741500-ff94-4836-bda1-a7ed5023abc7" height="80%" width="80%" alt="Splunk Log Analysis"/>
<br />
<br />
Doing diligence and checking if this is a malicious file I got the hash and uploaded it to virus total and discovered that it is blacksun ransomware.<br/>
<img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/149ce6ef-ccc0-4da0-b476-76624a460be7" height="80%" width="80%" alt="Splunk Log Analysis"/>
<img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/06e4aa24-5507-4006-8d0d-f4e643100a9e" height="80%" width="80%" alt="Splunk Log Analysis"/>
<br />
<br />
Further evidence of the blacksun ransomware infecting the host machine, the random string of characters "whwdgqg" and blacksun on various files and programs on the machines.<br/>
<img src="https://github.com/KirkDJohnson/Splunk-Ransomware-Analysis/assets/164972007/6490f5fa-27de-4634-a491-6ec0797fefd9" height="80%" width="80%" alt="Splunk Log Analysis"/>
<br />
<br />


<h2>Thoughts</h2>

This lab/exercise posed quite a challenge as I struggled to grasp the significance of OUTSTANDING_GUTTER[.]exe, despite sensing that something was awry. Initially, I couldn't discern how it infiltrated the host, and my research on the binary yielded no malicious indicators. It wasn't until I delved into PowerShell that the puzzle pieces began to fall into place. This experience served as a valuable lesson, emphasizing the importance of investigating the origin and nature of suspicious elements, even when their presence seems inexplicable. I also found it peculiar that the initial PowerShell script didn't directly install the ransomware "script.ps1" but instead navigated through several steps before initiating the download. Nonetheless, the exercise provided invaluable hands-on experience with Splunk, honing my skills in detecting malicious activity and refining my research and problem-solving abilities.






<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>

