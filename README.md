# Solorigate - An aggregated view for Defenders
### Table of contents

------------
- [Introduction](#Introduction)
- [Indicators](#Indicators)
  -	IP addresses
  -	Domains
  -	Hashes
	-	MD5
	-	SHA256
	-	SHA1
- [Detection](#Detection) 
	-	YARA Rules
	-	MITRE ATT&CK Mapping
	-	Splunk Query
	-	Sysmon Queries
	-	Sigma Query
	-	Rules by Fire Eye
	-	STIX Object
- [Mitigations](#Mitigation)
	-	Kill switch
	-	Playbooks
- [Credits and Further Reading](#Credits-and-Further-Reading)


------------
### Introduction
On the 8th of December 2020, the CEO of FireEye, a global security vendor announced that their systems had been comprimised by a sophisticated threat actor, supposedly state sponsored. 

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

A list of **sha1 indicators** can be found [here](https://github.com/cyware-labs/Solorigate/blob/main/data/sha1.indicators "here")

##### [SHA1 Indicators](https://github.com/cyware-labs/Solorigate/blob/main/data/sha1.indicators "SHA1 Indicators")

### Detection
Shortly after discovery of the Orion hack and indicators, global security vendor, FireEye also relaeased a **YARA rule** which is capable of detecting the trojanised version of Orion.

The same can be found [here](https://github.com/cyware-labs/Solorigate/blob/main/data/sunburst.yara "here")

##### [YARA Rule](https://github.com/cyware-labs/Solorigate/blob/main/data/sunburst.yara "YARA Rule")

We have also aggregated a mapping to the **MITRE ATT&CK** framework for this campaign as well. 

This mapping to ATT&CK can be found [here](https://github.com/cyware-labs/Solorigate/blob/main/data/ATT%26CK_mapping.md "here")

##### [MITRE ATT&CK Mapping](https://github.com/cyware-labs/Solorigate/blob/main/data/ATT%26CK_mapping.md "MITRE ATT&CK Mapping")

If the victim is infected by the backdoor, the malware then proceeds to perform some additional downloads for further persistance. This can be monitored by the following splunk query. Note: This query uses Zeek logs as a data source, but can be mapped to a source of your choice

This Splunk query can be found [here](https://github.com/cyware-labs/Solorigate/blob/main/data/splunk.query)

##### [Splunk Query](https://github.com/cyware-labs/Solorigate/blob/main/data/ATT%26CK_mapping.md "MITRE ATT&CK Mapping")

We also have aggregated a series of Sysmon queries which can be monitored for potential use of the Sunburst backdoor. 

These Sysmon queries can be found [here](https://github.com/cyware-labs/Solorigate/blob/main/data/sysmon.query)

##### [Sysmon Queries](https://github.com/cyware-labs/Solorigate/blob/main/data/sysmon.query)

The intelligence community has also identified another webshell, 'SUPERNOVA' which has been used to laterally move across the network. Shortly after identification the community has also created sigma queries to detect access to SUPERNOVA webshell.

This Sigma query can be found [here](https://github.com/Neo23x0/sigma/blob/master/rules/web/web_solarwinds_supernova_webshell.yml)

##### [Sigma Queries](https://github.com/Neo23x0/sigma/blob/master/rules/web/web_solarwinds_supernova_webshell.yml)

Global threat intelligence provieder Fire Eye has also released a series of Snort and YARA rules to detect Sunburst and Teardrop malwares used in Solorigate. These rules can be found [here](https://github.com/fireeye/sunburst_countermeasures/tree/main/rules)

##### [Rules by Fire Eye](https://github.com/fireeye/sunburst_countermeasures/tree/main/rules)

Along with this, we have also created a STIX 2.1 object containing indicators related to the Solawinds attack. This can be found [here](https://github.com/cyware-labs/Solorigate/blob/main/data/stix.json). The STIX data can also be visualzed for a better overview [here](https://oasis-open.github.io/cti-stix-visualization/)

##### [STIX File](https://github.com/cyware-labs/Solorigate/blob/main/data/stix.json)

### Mitigation

The intelligence community has also discovered that this particular strain of trojan contains a **kill switch** which kills itself if the domain *.avsvmcloud[.]com resolves to one of these IP's.

This list can be found [here](https://github.com/cyware-labs/Solorigate/blob/main/data/kill_switch.indicators "here")

##### [KILL Switches](https://github.com/cyware-labs/Solorigate/blob/main/data/kill_switch.indicators " KILL Switches")

### Playbooks
Since the attack, TrustedSec has released an **incident response playbook** that can be found [here](https://www.trustedsec.com/blog/solarwinds-backdoor-sunburst-incident-response-playbook/ "here")

##### [Incident response playbook](https://www.trustedsec.com/blog/solarwinds-backdoor-sunburst-incident-response-playbook/ "Incident response playbook")

### Credits-and-Further-Reading

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
- https://www.logpoint.com/en/blog/detecting-solarwinds-orion-attack/
- https://www.cisecurity.org/ms-isac/solarwinds/
- https://github.com/sophos-cybersecurity/solarwinds-threathunt/blob/master/iocs.csv
- https://labs.sentinelone.com/solarwinds-understanding-detecting-the-supernova-webshell-trojan/
- https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/trustwaves-action-response-to-the-fireeye-data-breach-solarwinds-orion-compromise/
- https://www.dragos.com/blog/industry-news/responding-to-solarwinds-compromise-in-industrial-environments/
- https://www.sumologic.com/blog/monitoring-solarwinds-supply-chain-attack-with-cloud-siem/
- https://github.com/davisshannon/Splunk-Sunburst
- https://www.fortinet.com/blog/threat-research/what-we-have-learned-so-far-about-the-sunburst-solarwinds-hack
- https://www.mcafee.com/blogs/other-blogs/mcafee-labs/additional-analysis-into-the-sunburst-backdoor/
- https://www.graylog.org/post/sunburst-backdoor-what-to-look-for-in-your-logs-now-interview-with-an-incident-responder
- https://www.hornetsecurity.com/en/threat-research/solarwinds-sunburst-backdoor-assessment/
- https://www.splunk.com/en_us/blog/security/sunburst-backdoor-detections-in-splunk.html
- https://blog.runpanther.io/detecting-sunburst-malware-with-panther/
- https://success.trendmicro.com/solution/000283368
- https://www.varonis.com/blog/solarwinds-sunburst-backdoor-inside-the-stealthy-apt-campaign/
- https://otx.alienvault.com/pulse/5fd8289cab970607370cf812
- https://www.varonis.com/blog/solarwinds-sunburst-backdoor-inside-the-stealthy-apt-campaign/
- https://unit42.paloaltonetworks.com/fireeye-solarstorm-sunburst/
- https://blog.malwarebytes.com/detections/backdoor-sunburst/
- https://www.optiv.com/solarwinds-orion-compromise
- https://securityboulevard.com/2020/12/detecting-sunburst-solarigate-activity-in-retrospect-with-zeek-a-practical-example/
