 RE-Toolkit
============

Linux-based toolkit distribution designed for reverse engineers, malware analysts and incident responders. The toolkit includes security tools such as debuggers, disassemblers, decompilers, static and dynamic analysis utilities, network analysis and many others. 

#### The RE-Toolkit will be used on **Botnet Mitigation Course** for setting up the lab environment in order to perform static and dynamic code analysis on malware samples.
 

Compatibility and Requirements
------------------------------
* Tested on [Ubuntu 20.04.1 LTS (Focal Fossa)](https://releases.ubuntu.com/20.04/)
* Compatible and tested with [Python ver 3.9.1](https://www.python.org/)

Usage
-----
Reverse Engineering toolkit is a open-source toolset that helps reverse engineers, malware analysts and incident responders to perform advance code analysis using debuggers, disassemblers, decompilers etc. 


The tool kit consists of:

| Plugins | README |
| ------ | ------ |
| Volatility | [Volatility](https://github.com/volatilityfoundation/volatility) |
| Burp | [Burp](https://portswigger.net/burp) |
| AnalyzePDF | [AnalyzePDF.py](https://github.com/hiddenillusion/AnalyzePDF/tree/5622db7ad3ac8ddf629fa6cf4ba46f34a2341338) |
| CapTipper | [ CapTipper v0.3](https://github.com/omriher/CapTipper) |
| Ciphey| [Ciphey](https://github.com/Ciphey/Ciphey/tree/8e22e500d5291fa686d52df2f47c234b6f469ba9) |
| Exescan | [Exescan](https://github.com/cysinfo/Exescan/tree/ad993e3aab3a25e932af083e5d06be7182411704) |
| IOCextractor | [IOCextractor](https://github.com/bworrell/IOCextractor/tree/04a4c87e9564f70469a4a23c4bccdc95c042a975) |


Installation
-----
The toolkit requires [Python V3+](https://www.python.org/) to run.

```sh
$ apt-get install git -y
$ cd /home/$SUDO_USER
$ git clone --recursive https://github.com/upxnoops/RE-Toolkit
$ chmod +x /home/$SUDO_USER/RE-Toolkit/setup.sh
$ /home/$SUDO_USER/RE-Toolkit/setup.sh
```

#### The toolkit should be instaled on the investigator workstation!!


Todos
-----
* Add more tools developed by the open-source comunity. 
* Check for updates and compatibility 

License
-----
[MIT](https://en.wikipedia.org/wiki/MIT_License)
