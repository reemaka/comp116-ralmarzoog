### set1.pcap
1. How many packets are there in this set?

    > 861

2. What protocol was used to transfer files from PC to server?

    > TCP

3. Briefly describe why the protocol sued to transfer the files is insecure?
    >
4. What is the secure alternative to the protocol used to transfer the files?
    > 
5. What is the IP address of the server?

    > 192.168.99.130

6. What was the username and password used to access the server?

    > username: defcon
    > password: m1ngisablowhard 

7. How many files were transferred from PC to server?

    > 6

8. What are the names of the files transferred from PC to server?

    > CDkv69qUsAAq8zN.jpg
    > CJoWmoOUkAAAYpx.jpg
    > CKBXgmOWcAAtc4u.jpg
    > CLu-m0MWoAAgjkr.jpg
    > CNsAEaYUYAARuaj.jpg
    > COaqQWnU8AAwX3K.jpg

9. Extract all the files that were transferred from PC to server.

### set2.pcap
10. How many packets are there in this set?

    > 77982

11. How many plaintext username-password pairs are there in this packet set? Please count any anonymous or generic accounts.

    > 1. larry@radsot.com : Z3lenzmej

12. Briefly describe how you found the username-password pairs.

    > Searched for "login" in the packets on Wireshark. Followed the TCP Stream for each of the search results.

13. For each of the plaintext username-password pair that you found, identify the protocol used, server IP, the corresponding domain name (e.g., google.com), and port number.

    >  1. SMTP, 54.240.13.8, a13-8.smtp-out.amazonses.com 

14. Of all the plaintext username-password pairs that you found, how many of them are legitimate?

    > 1

### set3.pcap
15. How many plaintext username-password pairs are there in this packet set? Please count any anonymous or generic accounts.  

    > 1. seymore : butts

16. For each of the plaintext username-password pair that you found, identify the protocol used, server IP, the corresponding domain name (e.g., google.com), and port number.

    > 1. HTTP, forum.defcon.org

17. Of all the plaintext username-password pairs that you found, how many of them are legitimate?

    > 0

18. Provide a listing of all IP addresses with corresponding hosts (hostname + domain name) that are in this PCAP set. Describe your methodology.

    > The list is in the file called set3hosts.txt. I used tshark to generate this list.

