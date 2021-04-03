<h1> Welcome to our Final Project for CSCE5550 </h1>

Ransomware is a malware family that uses security techniques such as cryptography to hijack user files and associated resources and requests cryptocurrency in exchange for the locked data. There is no limit to who can be targeted by ransomware since it can be transmitted over the internet. Like traditional malware, ransomware may enter the system utilizing “social engineering, malware advertising, spam emails, take advantage of vulnerabilities, drive-by downloads or through open ports or by utilizing back doors”. But in contrast to traditional malware, even after removal, ransomware influence is irreparable and tough to alleviate its impact without its creator's assistance. This kind of attack has a straightforward financial implication, which is fueled by encryption technology, cyber currency. Therefore, ransomware has turned into a profitable business that has obtained rising popularity between attackers. 

In this project, we propose to design, develop and study different stages of ransomware attack using a web server and its remote database server. Below are the three major parts of this project: 
1. Create a desktop Ransomware 
2. Detect the ransomware infection
3. Remediation or restoring services and data after the attack

<h2> Create a desktop Ransomware  </h2>

In this project we will develop a desktop application that communicates over HTTP. This application will be executed on the victim's machine and serves as a client to execute the attack. This application can be controlled by a remote attacker. The remote attacker has a pre-generated RSA keypair (Apriv and Apub) of which the public key is embedded in the client application. The client creates its own set of public and private keys (Cpriv and Cpub), of which the private key (Cpriv) is immediately encrypted by attackers public key (Apub). Once this is done, the client can start the attack by starting encryption with Cpub. The victim can be sent an extortion message through a html file.
This ransomware will use a http service that can be utilized by the attacker to manage the ransomware attack after attackers file are encrypted. The client and http service together can help in creating a focused attack example, decrypting specific file type, decrypting certain locations etc. The client and remote service together can be used to facilitate decryption after all attackers demands are fulfilled. 

![image](https://user-images.githubusercontent.com/80862273/111945861-7068fe80-8aa8-11eb-8986-1b5a7c4cdc70.png)

<h2> How to user </h2>

This project has two major components
1. Attacker program (attacker.py): This program creates the attackers key pair and stores them to /keystore in users /Documents. This program is also reponsible for decrypting victims encrypted private key.
2. Victim program (ransomware.py): This program using attackers public key ./public.pem carrys out the ransomware attack. Once the attack is complete, this program also looks at desktop for the unlock key to decrypt the system.

<h3> Attack Instructions </h3>
1. Execute ransomware.py with public.pem in the same folder. This will result in encryption of all user files.
2. Share the 'Email_Me_After_Paying.pemcry' with attacker after following instructions from RANSOM_NOTE.TXT on Desktop.
3. Execute attacker.py with 'Email_Me_After_Paying.pemcry' in the same folder and this will generate a new pem file 'PUT_ON_DESKTOP.pem'.
4. Share the PUT_ON_DESKTOP.pem file with victim and place this file on victims Desktop.
5. attacker will automatically run decryption and end program after completion.