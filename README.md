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

| Plugin | README |
| ------ | ------ |
| Dropbox | [plugins/dropbox/README.md](www.google.com)[PlDb] |
| GitHub | [plugins/github/README.md][PlGh] |

* 
* 
* 

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
