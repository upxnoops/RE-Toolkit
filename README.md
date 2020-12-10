 RE-Toolkit
============

Linux-based toolkit distribution designed for reverse engineers, malware analysts and incident responders. The toolkit includes security tools such as debuggers, disassemblers, decompilers, static and dynamic analysis utilities, network analysis and many others. 

The RE-Toolkit will be used on "Botnet Mitigation" course for setting up the lab environment in order to perform static and dynamic analysis on malware samples.
 

Compatibility and Requirements
------------------------------
* Tested on Ubuntu 20.04.1 LTS (Focal Fossa)
* Compatible and tested Python versions: 3
* etc....

Usage
-----
This program helps to install the toolkit for performing Reverse Engineering. 

Instructions
-----


apt-get install git -y && 

cd /home/$SUDO_USER && 


git clone --recursive https://github.com/upxnoops/RE-Toolkit && chmod +x /home/$SUDO_USER/RE-Toolkit/setup.sh && /home/$SUDO_USER/RE-Toolkit/setup.sh
