# Solorigate - An aggregated view for Defenders
### Table of contents

------------
- [Introduction](#Introduction)
- [Indicators](#Indicators)
  -	[IP addresses](#IP Adresses)
	-	[Domains](#Domain Indicators)
	-	Hashes
		-	[MD5](#MD5 Inidcators)
		-	[SHA256](#SHA256 Indicators)
- [Detection](#Detection) 
	-	[YARA Rules](#YARA Rule)
	-	[MITRE ATT&CK Mapping](#MITRE ATT&CK Mapping)
- Mitigations
	-	[Kill switch]
	-	[Playbooks]
- [Credits and further references]


------------
### Introduction
On the 8th of December 2020, the CEO of FireEye a global security vendor, announced their systems had been comprimised by a sophisticated threat actor, supposedly state sponsored. 

Shortly after this announcement FireEye further disclosed that not only FireEye, but also multiple other companies had been comprimised by the supposedly state sponsored threat actor via a supply chain attack [dubbed campaign 'UNC2452'].

This attack was carried out by adding a malicious trojan implant to the IT management software 'Orion' from the company Solarwinds.

Solarwinds is one of the most prominent companies in the US, with a client base of over 33,000 companies, of which there are 425 of the Fortune 500 companies and the top 10 telecom operators in the United States.

Solarwinds has since said over 18,000 of its customer companies have been infected byt this highly sophisticalted, allegedly state sponsored cyber attack.

### Indicators
After analysis, the threat intelligence community has uncovered various indicators of compromise that indicate the presence of the malware implanted by the threat actor responsible for campaign UNC2452. This repository primarily aims at aggregating all of these indicators for future perusal.

A list of **IP indicators** can be found [here](https://github.com/cyware-labs/Solorigate/blob/main/data/ip.indicators "here")
##### [IP Addresses](https://github.com/cyware-labs/Solorigate/blob/main/data/ip.indicators "IP Addresses")

A list of **domain indicators** can be found [here](https://github.com/cyware-labs/Solorigate/blob/main/data/domains.indicators "here")

##### [Domain Indicators](https://github.com/cyware-labs/Solorigate/blob/main/data/domains.indicators "Domain Indicators")
A list of **md5 hash indicators** can be found [here](https://github.com/cyware-labs/Solorigate/blob/main/data/md5.indicators "here")

##### [MD5 Inidcators](https://github.com/cyware-labs/Solorigate/blob/main/data/md5.indicators "MD5 Inidcators")

A list of **sha256 indicators** can be found [here](https://github.com/cyware-labs/Solorigate/blob/main/data/sha256.indicators "here")

##### [SHA256 Indicators](https://github.com/cyware-labs/Solorigate/blob/main/data/sha256.indicators "SHA256 Indicators")

### Detection
Shortly after discovery of the Orion hack and indicators, global security vendor, FireEye also relaeased a **YARA rule** which is capable of detecting the trojanised version of Orion.

The same can be found [here](https://github.com/cyware-labs/Solorigate/blob/main/data/sunburst.yara "here")

##### [YARA Rule](https://github.com/cyware-labs/Solorigate/blob/main/data/sunburst.yara "YARA Rule")

We have also aggregated a mapping to the **MITRE ATT&CK** framework for this campaign as well. 

This mapping to ATT&CK can be found [here](https://github.com/cyware-labs/Solorigate/blob/main/data/ATT%26CK_mapping.md "here")

##### [MITRE ATT&CK Mapping](https://github.com/cyware-labs/Solorigate/blob/main/data/ATT%26CK_mapping.md "MITRE ATT&CK Mapping")

### Mitigation

The intelligence community has also discovered that this particular strain of trojan contains a **kill switch** which kills itself if the domain *.avsvmcloud[.]com resolves to one of these IP's.

This list can be found [here](https://github.com/cyware-labs/Solorigate/blob/main/data/kill_switch.indicators "here")

##### [KILL Switches](https://github.com/cyware-labs/Solorigate/blob/main/data/kill_switch.indicators " KILL Switches")

### Playbooks
Since the attack, TrustedSec has released an **incident response playbook** that can be found [here](https://www.trustedsec.com/blog/solarwinds-backdoor-sunburst-incident-response-playbook/ "here")

##### [Incident response playbook](https://www.trustedsec.com/blog/solarwinds-backdoor-sunburst-incident-response-playbook/ "Incident response playbook")
###Credits and Further reading
The intelligenec community is a vibrant community that strives to help one another, especially during times of crisis. On that note, below we have compiled various materials we found to be extremely helpful and comprehensive.

As the saying goes - ***United we stand, Divided we fall !***

Stay tuned to this repository for more exclusive playbooks and detection methods !

- https://us-cert.cisa.gov/ncas/alerts/aa20-352a
- https://cyber.dhs.gov/ed/21-01/#supplemental-guidance
- https://us-cert.cisa.gov/ncas/current-activity/2020/12/23/cisa-releases-cisa-insights-and-creates-webpage-ongoing-apt-cyber
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://github.com/fireeye/sunburst_countermeasures
- https://www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html
- https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/
- https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/
- https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/
- https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/
- https://techcommunity.microsoft.com/t5/azure-sentinel/solarwinds-post-compromise-hunting-with-azure-sentinel/ba-p/1995095
- https://techcommunity.microsoft.com/t5/azure-active-directory-identity/understanding-quot-solorigate-quot-s-identity-iocs-for-identity/ba-p/2007610
- https://twitter.com/JohnLaTwC/status/1341116928350277632
- https://www.solarwinds.com/securityadvisory
- https://blog.reversinglabs.com/blog/sunburst-the-next-level-of-stealth
- https://www.mcafee.com/blogs/other-blogs/mcafee-labs/additional-analysis-into-the-sunburst-backdoor/
- https://twitter.com/NSACyber/status/1339759778923474944 https://media.defense.gov/2020/Dec/17/2002554125/-1/-1/0/AUTHENTICATION_MECHANISMS_CSA_U_OO_198854_20.PDF
- https://research.checkpoint.com/2020/sunburst-teardrop-and-the-netsec-new-normal/
- https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/sunburst-supply-chain-attack-solarwinds
- https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-attacks-stealthy-attackers-attempted-evade-detection
- https://unit42.paloaltonetworks.com/solarstorm-supply-chain-attack-timeline/
- https://github.com/shewhohacks/Navigator-files/blob/main/SolarStorm.json
