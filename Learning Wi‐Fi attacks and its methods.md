## Basic Working of Wi-Fi.

Radio Signals: Wi-Fi works by transmitting data over radio waves. Devices communicate in the Wi-Fi network by sending and receiving radio signals.

Access Points (APs) act as the central hub for Wi-Fi connections. They receive data from connected devices and transmit it to other devices on the network.

Network Identification: Wi-Fi networks are identified by their Service Set Identifier (SSID) which in simple terms is the network name.

Authentication and Encryption: When a device connects to a Wi-Fi network, it undergoes an authentication process to verify its identity. Wi-Fi protocols such as WPA2 or WPA3 are used to secure data transmissions over the network.

## Types of Wi-Fi.

802.11 b/g/n: These are older Wi-Fi standards operating primarily in the 2.4 GHz frequency band. They offer relatively slower speeds compared to newer standards.

802.11 ac: Also known as Wi-Fi 5, this standard operates in both the 2.4 GHz and 5 GHz bands, providing faster speeds and improved performance compared to older standards.

802.11 ax: Also referred to as Wi-Fi 6, this is the latest Wi-Fi standard offering even higher speeds, lower latency, and improved efficiency, especially in high-density environments.

## Types of Wi-Fi Attacks.

Eavesdropping (Passive Attacks): Attackers can intercept Wi-Fi signals to capture sensitive information such as passwords or financial data without actively engaging with the network.

Man-in-the-Middle (MITM) Attacks: In this type of attack, the attacker intercepts communication between two parties, potentially altering or eavesdropping on the data being transmitted.

Brute Force Attacks: Attackers attempt to crack Wi-Fi passwords by systematically trying all possible combinations until they find the correct one.

Evil Twin Attacks: Attackers set up rogue access points with the same SSID as a legitimate network, tricking users into connecting to it and potentially exposing their data.

Denial of Service (DoS) Attacks: Attackers flood a Wi-Fi network with an overwhelming amount of traffic, causing it to become unavailable to legitimate users.

WPS Vulnerabilities: Wi-Fi Protected Setup (WPS) is a feature that simplifies the process of connecting devices to a Wi-Fi network, but it can also introduce security vulnerabilities if not properly configured, allowing attackers to gain unauthorized access.

## Connecting the wireless adapter,

![WhatsApp Image 2024-03-03 at 09 39 18_2829d0ff](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/73205978-bf50-4f8b-b6cd-c9459edeb17e)

## 2. Perform Wi-Fi fingerprinting.

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/584c1b34-480a-4d52-b2dc-729f5d8e36ef)

## 3. Create an Access point with any Wi-Fi encryption standard and start testing the security of that connection using any Wi-Fi security testing tools, which should include (Aircrack-Ng, Wifite, not limited). Try to capture the 4-way handshake using these methods.

> So our target here Nifal so we will be attacking this network and it's using the wpa-p

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/584c1b34-480a-4d52-b2dc-729f5d8e36ef)

> Handshake is captured.

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/2a0c65da-c47f-4774-9225-4f7a32cfc0ac)

> It saves it as a pcap file and try to crack the password using the specified wordlist and we can see the key after cracking the i.e 123456789
> So we try analyze the wireshark pcap that is saved along with this we can see that the 4 hand shake was captured.

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/cca260fa-f19f-4bc1-bfb2-ac6cfbde031e)

## 4. After capturing the required files for testing, use dictionary generation and password cracking tools to crack the Wi-Fi password.
> To generate a wordlist, we can use the crunch command.
`crunch 8 12 012345678abcdefghijklmnopqrstuvwxyz -o wordlist.txt`

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/37e90a74-2f8d-404e-aa61-b0b85a0572be)

## 5. Use Rouge AP (WifiPhisher) to create an Evil twin, perform a basic phishing attack using this rouge AP, and document the difference between the two attacks you have performed.

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/0db80af5-d39f-4c68-9c19-f299d52f78df)

> Then run WifiPhisher, we have to select which wifi fake have to create.

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/d00c9240-fc16-42b3-8418-9e697f348ba3)

> We have to select what phishing we have to perform. I have selected auth login

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/e2fd92e3-6b82-461c-bb5a-8276c41128f2)
![WhatsApp Image 2024-03-03 at 10 30 59_0d40d582](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/d7aee839-daf3-46ee-9452-d2887f14af9b)

> So with help of WifiPhisher we created fake Nifal wifi and we will try to connect ot it.

![WhatsApp Image 2024-03-03 at 10 33 37_d045a731](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/4b12e02b-3d4f-4d67-a2c8-73035eb891a2)

> So as soon as the android device is connected it shows in the screen.

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/514911ad-4cdf-4dd2-b3d2-64c4c1a7587f)

> And we enter the password in the website it reflected back when we close the tool.

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/20c5f1fe-d179-449a-a280-e93bac3c8965)

## 6. Learn the protocol level working of WPA3 and how it differs from WPA2.

WiFi Protected Access 3 (WPA3) is the security protocol for WiFi networks succeeding WPA2. It enhances the security features and addresses some of the security vulnerabilities provided by WPA2.

Key Establishment and Authentication WPA3 introduced a handshake protocol called Simultaneous Authentication of Equals (SAE), which is based on DragonFly Key Exchange Protocol. This mitigated the vulnerabilities present in WPA2's four way handshake, hence making the WPA3 resistant to offline dictionary attacks and password guessing attacks.

Encryption WPA3 introduced support for Galois Counter Mode (GCMP). This offers similar security to Chaining Message Authentication Code Protocol (CCMP) but is more efficient in terms of processing power, which can improve battery life of the devices.

Protection against Brute Force Attacks WPA3 incorporated stronger protections against brute force attacks through the use of hash to group feature in the DragonFly handshake protocol. This made it significantly harder for attackers to guess the passphrase by making repeated brute force attempts.

Forward Secrecy WPA3 offers perfect forward secrecy ensuring that even if an attacker were to compromise the network's security key in the future, they would not be able to decrypt past data transmitted in the network.
