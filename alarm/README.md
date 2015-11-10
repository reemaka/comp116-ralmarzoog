## Incident Alarm
1. Identify what aspects of the work have been correctly implemented and what have not.

    > To my knowledge, everything has been correctly implemented

2. Identify anyone with whom you have collaborated or discussed the assignment.

    > Obaid Farooqui, Melissa Blotner

3. Approximate number of hours spent on the assignment.

    > 4 hours



### Questions
1. Are the heuristics used in this assignment to determine incidents
    "even that good"?

    > Many of the heuristics used will result in false positives; for example, a NULL scan may be detected even if it is not malicious and some strings of numbers will fit the criteria we use to determine if a number is a credit card number but it may not actually be a credit card number. Furthermore, we check for some of the incidents by checking for keywords in the payload. If an attacker did not include the keyword, we may not detect the incident. So, though th heuristics will catch many potential incidents, there may be some false positives and false negatives.

2. If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?

    > Detect more specific Nmap incidents, detect more incidents in general, support PCAP file reading, try to avoid more false negatives by detecting specific attributes of scans rather than just the presence of "nikto" or "nmap" as the case may be.

