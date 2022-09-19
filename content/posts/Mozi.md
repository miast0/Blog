---
title: "An analysis of the IoT Botnet Mozi"
description: 'An analysis of the IoT P2P botnet Mozi'
date: 2022-09-08T17:42:34+01:00
draft: true
toc: true
images:

tags: 
  - malware
  - reverse engineering 
  - threat analysis
---
This post is a shortened amalgamation of the research project apart of my Bsc. in IT Management.

# Contents
1. [Background Research](#background)
2. [Mozi function](#function)  
	1.[Persistence](#persistence)  
	2.[Reconnaissance](#recon)  
	3.[Infection](#infection) 
3. [Network Analysis](#network)
4. [Defence Strategies](#defence)

## Background Research {#background}
Mozi is an **I**nternet **o**f **T**hings (**IoT**) **P**eer-to-**P**eer (**P2P**) botnet. Mozi specifically targets insecure and outdated IoT devices through a number of different vulnerabilities and weak telnet passwords. Mozi has been used to conduct DDoS attacks, data exfil and potentially click fraud. 

Mozi was initially discovered around September 2019. 


### Yara Rule  
``` YARA
rule Mozi_yara_rule
{
	meta:
		author = "Dean Brennan"
		description = "Yara rule to detect Mozi from UPX p_info missing bytes and ELF MIPS format"
		version  = "1.0"
	strings:
		$elfhex = {?? 45 4C 46}
		//Yara rule to match for ELF in hex
		$upxhex = {55 50 58 21 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00} 
		//Yara rule to match for UPX! followed by the empty p_info bytes
	condition:
		all of them
}
 ```
