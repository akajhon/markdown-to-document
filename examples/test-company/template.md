---
title: "Report CTI Example"
subtitle: "This is a CTI report"
author: 
  - Your Company
date: \today
lang: "en-US" 

# Layout Configs
toc: true
toc-own-page: true
toc-title: "Summary"
numbersections: true
titlepage: true
listings: true
listings-no-page-break: true
highlight-style: tango
papersize: "a4"

# Visual Configs
titlepage-logo: "logo.png"
logo-width: 125mm
titlepage-background: "background.jpg"
titlepage-text-color: "000000"
titlepage-rule-color: "0033A0" 
titlepage-rule-height: 2

# Header and Footer
header-left: "Random Company - \\thetitle"
header-right: "\\includegraphics[width=30mm]{logo.png}"
footer-left: "\\footnotesize Random Company CTI\\hspace{2pt} | \\hspace{2pt} Confidential document"
footer-right: "Page \\thepage\\hspace{2pt} of \\pageref{LastPage}"

# Table Configs
table-use-row-colors: true
table-caption: "Table"

# Font Configs
mainfont: "Ubuntu"
sansfont: "Georgia"
monofont: "Courier New"
fontsize: 11pt
geometry: "left=2.5cm,right=2.5cm,top=2.5cm,bottom=2.5cm"

header-includes:
    - \usepackage{lastpage}
    - \usepackage{graphicx}
    - \usepackage{caption}
    - \usepackage{indentfirst}
    - \usepackage{tcolorbox}
    - \usepackage{listings}
    - \usepackage{fontspec}
    - \usepackage{ulem}
...

\setlength{\parindent}{1.5cm}

# Evil Company Data Leak - Cyber Threat Intelligence Report

# Introduction

::: {.indented}
The Cyber Threat Intelligence (CTI) team is responsible for monitoring the Deep & Dark Web to protect brand integrity and prevent the exposure of sensitive information. This proactive monitoring aims to identify Zero-Day threats, data leaks, credential leaks, new vulnerabilities, and ransomware activities that may affect the organization, manufacturers, or partners.
:::

# Executive Summary

::: {.indented}
A threat actor known as "DarkPhantom" claimed on a notorious underground forum to have access to approximately **10 million** customer records from Evil Company's authentication systems. This includes compromised credentials from the company's Single Sign-On (SSO) and Lightweight Directory Access Protocol (LDAP) systems.
:::

# Threat Details

::: {.indented}
According to the forum post, the attacker allegedly breached Evil Company's authentication servers (auth.evilcompany.com), leading to the exfiltration of millions of user credentials and sensitive information. The attacker claims to have obtained the following data:
:::

- Encrypted passwords (SSO & LDAP)
- API keys
- Authentication tokens
- Private encryption keys
- Internal employee directory information

::: {.indented}
While the SSO passwords are encrypted, the attacker asserts that they can be decrypted using the available key files. Similarly, the hashed LDAP passwords may be cracked. The attacker, however, admitted their lack of computational resources to conduct brute-force decryption and is seeking assistance from other cybercriminals in exchange for a portion of the stolen data.
:::

The attacker has shared the following samples as proof:

- **Sample File 1:** A list containing 250,000 affected email addresses and domains.
- **Sample File 2:** A database dump with sensitive authentication information, including:
    - User IDs
    - Encrypted passwords
    - User roles and permissions
    - API access logs
    - Multi-Factor Authentication (MFA) statuses
- **Sample File 3:** Encrypted private keys allegedly linked to Evil Company's internal services.

# Threat Actor Profile

::: {.indented}
The threat actor "DarkPhantom" is a relatively new member of the cybercrime community, registered on the dark web forum in March 2025. They have no significant reputation but have made several posts related to credential leaks and database breaches. In addition to their forum activity, they also operate on encrypted messaging platforms, where they offer stolen data for sale or trade.
:::

# Forum Post by the Attacker

Message from the attacker.

\lstset{
      basicstyle=\ttfamily\footnotesize,
      columns=fullflexible,
      breaklines=true,
      frame=none,
      xleftmargin=10pt,
      xrightmargin=10pt
    }
\newtcolorbox{forum}{
      colback=gray!3,
      colframe=gray!30,
      boxrule=0.3pt,
      left=5pt,
      right=5pt,
      top=3pt,
      bottom=3pt,
      arc=1pt,
      fontupper=\ttfamily\footnotesize
    }

\begin{forum}
\begin{lstlisting}
Evil Company authentication servers breached (auth.evilcompany.com)

Hey,
I have successfully breached Evil Company's authentication servers, affecting their SSO and LDAP systems.
Over 10 million user records have been stolen, including encrypted passwords, API keys, and internal authentication data.

The encrypted passwords **can be decrypted**, but I need assistance to brute-force them. In exchange, I will share part of the stolen data.

Companies can pay to have their employee data removed before the full database is sold.

I'm also willing to trade for 0-day exploits.

PM me for offers.

Sample Data > []
Company List > []
Encryption Keys > []
\end{lstlisting}
\end{forum}

# Image of the Post

\begin{figure}[h]
    \centering
    \includegraphics[width=0.8\textwidth]{example.jpg}
    \captionsetup{justification=centering, singlelinecheck=false, format=plain}
    \caption{Extracted from Underground Forum}
\end{figure}

# Shodan Information

\begin{forum}
\begin{lstlisting}
Remote Desktop Protocol NTLM Info:
  OS: Windows Server 2019
  OS Build: 10.0.17763
  Target Name: EVILCOMPANY
  NetBIOS Domain Name: EVILCOMPANY
  NetBIOS Computer Name: EVILSRV001
  DNS Domain: evilcompany.com
\end{lstlisting}
\end{forum}

# Mitigation Recommendations

1. **Immediate Password Resets**: Force password resets for all affected users.
2. **MFA Enforcement**: Ensure multi-factor authentication is mandatory for all accounts.
3. **Network Segmentation**: Isolate critical authentication servers to prevent lateral movement.
4. **Log Analysis**: Review access logs for unusual login attempts or unauthorized access.
5. **Threat Hunting**: Proactively search for indicators of compromise (IOCs) related to this breach.
6. **Dark Web Monitoring**: Continue monitoring underground forums for further leaks or activity related to this incident.

# Conclusion

This breach highlights the growing threats posed by cybercriminals targeting enterprise authentication systems. Evil Company must take immediate action to mitigate potential damages and strengthen its security posture to prevent future incidents.

