## Use the tool NMAP [Command line only]to perform the below task. Run Wireshark in the background and capture only the necessary packets to showcase for the corresponding question.

a) Explain the subnet and use the NMAP Command to scan the services for the whole subnet.

A subnet, short for subnetwork, is a logical subdivision of an IP network. It allows for the division of a larger network into smaller, manageable parts. Subnetting is primarily used to improve network performance, security, and organization. Each device on a network is assigned an IP address, and subnetting helps in efficient routing of data packets within the network.

Command to scan entire subnet `nmap -sV <subnet/CIDR notation>`

Victim Machine
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/01c9874a-4811-4c35-a75e-6cb9d0109de5)

Attacker Machine
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/421dd0c5-c928-4193-9bf2-48d9d1978a10)

b) What is a firewall, and mention its types. Use the NMAP command to detect that a firewall protects the host.
* A firewall is a type of network security appliance that keeps an eye on and regulates inbound and outgoing network traffic in accordance with pre-established security rules. Its main goal is to defend devices and networks from malicious activity, assaults, and unauthorised access. It is possible to deploy firewalls using hardware, software, or a combination of the two. They function by looking at network traffic packets and comparing them to the administrator's preset rules or policies.

* A packet is permitted to get across the firewall if it matches a rule. If it doesn't fit any of the rules, it's either rejected or forwarded to another place for more examination.

firewall types
* Software firewall.
* Hardware firewall.
* Packet filtering firewall.
* Circuit-level gateway.
* Proxy service application firewall.

The NMAP command to detect if a host is protected by a firewall. Here’s an example of how you might do this:
`nmap -sS -p- <target-ip>`
`-sS` option tells NMAP to perform a SYN scan, which is a type of stealth scan. `-p-` option tells NMAP to scan all 65535 ports. This command will send a TCP SYN packet to each port on the target host. If the port is open, the target will respond with a SYN/ACK packet. If the port is closed, the target will respond with a RST packet. If there is no response, or the packet is dropped, it’s likely that a firewall is protecting the host.

Victim Machine when firewall is on
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/ce91ef9f-0668-41c8-bd66-6b46cf10fb5b)

Attacker Machine

There is no response. So it’s likely that a firewall is protecting the host
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/d1bd4a76-61d6-4113-a335-fe1c57a861f3)

Victim Machine when firewall is off
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/80e750bc-ff56-4102-84b3-67bd4a1b2028)

Attacker Machine
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/7c1c1426-d69b-40f0-afb6-fce5840df5fa)

c) Use the NMAP command to scan a network and determine which devices are up and running.
Command - nmap `-sn <ip>/<CIDR>`

Attacker Machine 
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/87cec6fc-d16d-4935-b944-40e0cf5395d7)

d) What are vertical and horizontal scanning?
* Horizontal scanning  sends requests to the same port on different hosts. Attackers use horizontal scanning to prepare for a mass attack.
* Vertical scanning sends requests to different ports on the same host. Attackers typically use vertical scanning to look for vulnerabilities in a preselected t

e) Use the NMAP command to scan multiple hosts. [HINT: Add hosts into a file and scan it].
Attacker Machine

WE need to add the ip address of the Victim Machine `10.11.130.209 to /etc/hosts file`.
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/18744b47-d4ce-4674-bd54-893b76dbdae7)

f) Use NMAP commands to export the output in XML format.

Attacker Machine
Use the `nmap -sV <target-ip> -oX name.xml`
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/5c96a154-0bd7-4681-a2f2-5e3df2496077)

g) Use the NMAP command to get OS information about a host.

Attacker Machine
`nmap -O <target-ip>`
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/6e5df216-da33-4ab6-8109-49e441b7e5fe)
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/1f2d3cac-97e0-44da-b116-ad321e7a9baf)

h) Explain ping sweeping and Perform ping sweeping using Nmap

Ping Sweep
A method of network reconnaissance called "ping sweeping" is used to find out which IP addresses are active and reachable within a network. To find out which IP addresses are reachable and available, it entails sending a string of ICMP echo request messages, or pings, to a variety of addresses, usually in a sequential manner.

Network administrators frequently use ping sweeping to map the network and find active hosts.

Nmap command to perform ping sweep - `nmap -sn <network address>/<CIDR>-.
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/52ed01d6-48a2-43b6-b298-9aabaa20a3e1)

Try these below questions after completing the above commands.

1. What is a web application firewall? How do you use Nmap to detect a WAF? Perform WAF fingerprint detection using NMAP.

* A Web Application Firewall (WAF) is a security tool designed to protect web applications from various attacks, such as SQL injection, cross-site scripting (XSS), and other common web exploits. WAFs monitor and filter HTTP traffic between a web application and the Internet, identifying and blocking malicious requests before they reach the application.
* To detect a WAF using Nmap, you can use its HTTP WAF fingerprinting feature. This feature sends specially crafted HTTP requests to the target web server and analyzes the responses to identify patterns that indicate the presence of a WAF.

`sudo nmap --script http-waf-fingerprint <target>`

Victim Machine when firewall is on
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/22d8d4a2-9cf6-448f-a170-0b5a649b2e55)

Attacker Machine
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/84538770-d09a-4edc-a30e-00ca45de9c93)

2.What is EXIF data? Tryto find EXIF data of images on a website using NMAP NSE.
EXIF DATA
-EXIF (Exchangeable Image File Format) data is a standard for storing metadata in image files, typically used by digital cameras and smartphones. This metadata can include information such as the camera model, exposure settings, GPS coordinates, and timestamps.

-To find EXIF data of images on a website using Nmap NSE (Nmap Scripting Engine), you can use the http-exif-spider script. This script crawls a website, downloads images, and extracts EXIF data from them. Here's how you can do it:

`sudo nmap --script http-exif-spider <website>`

Attacker Machine
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/e8345d66-c81a-460a-8399-f49595a16c26)

3. Use NMAP NSE to find all subdomains of the website.

All the nse scripts are loacated in `/usr/share/nmap/scripts/`
`sudo nmap --script dns-brute <website>`

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/e1c48d02-09dc-45bf-a0ef-348020fc99d5)
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/2e0a4a79-d4a9-4ee2-baff-4275efa19d5a)

4. Perform a vulnerability scan on the target host using NMAP NSE.

Command - `nmap -sV --script=vuln <target ip>`

Attacker Machine
![image](https://github.com/KVNuhman/cybersecurity-tools/assets/46161259/76d93208-e489-4822-addb-58aaf5266d01)
