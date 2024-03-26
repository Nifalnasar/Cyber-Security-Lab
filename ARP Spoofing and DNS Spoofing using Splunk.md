## TOOL USED HERE
### ETTERCAP
Ettercap is a comprehensive, open-source network security tool used for analyzing, monitoring, and manipulating network traffic in a computer network. Originally developed for Unix-like operating systems, it has since been adapted for Windows as well. Ettercap operates as a man-in-the-middle (MITM) attack tool, allowing cybersecurity professionals, penetration testers, and ethical hackers to inspect and modify data as it passes through a network.

### Familiarization with tool
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/491abb70-d5fe-4240-9677-c4a01c144c15)

So here we set the interface on which have to start sniffing and related attacks. Then we start sniffing on the interface.

## ARP SPOOFING
ARP spoofing is the process of linking an attacker’s MAC address with the IP address of a legitimate user on a local area network using fake ARP messages. As a result, data sent by the user to the host IP address is instead transmitted to the attacker.

### CAUSE OF ATTACK
The main cause of ARP spoofing attacks is the fundamental trust issue within the Address Resolution Protocol (ARP) itself. ARP is a network communication protocol that helps devices translate IP addresses, which are easy for humans to remember, into MAC addresses, which are the unique identifiers used by network devices.

### PREVENTION
We can prevent it by implementing the IDS(Intrusion detection system).
Using the Arp-spoof detecting software.

### PERFORMING THE ATTACK
First we discover all the hosts and choose the target on which we want to perform ARP spoofing attack.
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/f9404098-7996-4361-98de-e1e600fdba59)

To find the Victim gateway.
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/3a09d031-7f9b-4225-9002-4d00d5baf917)

So here the target is 192.168.21.128 and the target gateway is 192.168.21.2

Then we perform the ARP poisoning attack
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/cd39e571-0c55-4144-9b89-2e0b436c9c93)

Now we can see that we are able to see the traffic. So our attack is successful.

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/1e972f0c-4363-4467-a57b-4d3543e2fe6f)

### Splunk Logs
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/dc4b46be-fbf2-4ec9-abe9-7459360862de)

When analyze the Splunk reports we can see that http request was successful but there was no sign of showing ARP spoof.

## DNS SPOOFING
In a DNS spoofing attack, the attacker exploits vulnerabilities in the DNS resolution process to provide false information to a DNS resolver, which is responsible for translating domain names into IP addresses. The goal of DNS spoofing is to redirect users to a fraudulent website or to intercept sensitive information.

### CAUSE OF ATTACK
1. Weaknesses in DNS Protocol: The DNS protocol itself can have vulnerabilities that attackers exploit. For example, if the DNS messages are not adequately protected, an attacker might inject false DNS responses into the system.
2. Lack of DNS Security Extensions (DNSSEC): DNSSEC is a suite of extensions to DNS designed to add an additional layer of security by signing DNS data with cryptographic signatures. If DNSSEC is not implemented or configured incorrectly, it can leave the DNS system susceptible to spoofing attacks.

### PREVENTION
To prevent DNS spoofing, organizations and individuals should implement several key measures. Firstly, deploy DNS Security Extensions (DNSSEC) to authenticate and verify the integrity of DNS data through cryptographic signatures. Additionally, configure DNS resolvers to limit open access, ensuring they respond only to authoritative queries.

### PERFORMING THE ATTACK
To perform the attack we will be using the DNS spoof plugin that is available in Ettercap that we previously used.

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/096f93af-610e-40ad-acfb-0178c909a69b)

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/2b79785d-5dcc-4d2d-aec3-8c0e6f7ec4d7)

we will turn on the redirection and which website we spoof the DNS. So first start the Dns spoofing using the plugin in the Ettercap plugins.

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/8e91fa7a-c6c1-4a48-9aa5-79e708b7c93e)

So we can see that we have Dns_spoof plugin. After starting the Dns spoofing we will use Arp poisoning again to make the attack successful.

We will add all the gate way as the first target and others host as the second target. Now if we try to navigate to the specified website it should goto Apache server running on the attacker machine.
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/ec685187-9eb2-4e6c-9b38-8925bde66ef6)

So the attack is successful.

### Splunk Logs
![WhatsApp Image 2024-01-29 at 22 37 32_01bc50b5](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/ec3767d3-9a2a-473c-b71d-a19751e84aea)

So we can see in the Splunk logs that we were redirected to other website that is a Apache server.

