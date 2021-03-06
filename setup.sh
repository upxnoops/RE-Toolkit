#!/bin/bash -x

	echo "------------------------------"
	echo "- Update Ubuntu Sequence Starting -"
	echo "------------------------------"

check_exit_status() {

	if [ $? -eq 0 ]
	then
		echo
		echo "Success"
		echo
	else
		echo
		echo "[ERROR] Process Failed!"
		echo
		
		read -p "The last command exited with an error. Exit script? (yes/no) " answer

            if [ "$answer" == "yes" ]
            then
                exit 1
            fi
	fi
}

greeting() {

	echo
	echo "Hello, $USER. Let's update the system first."
	echo
}

update() {

        sudo apt-get update;

        sudo apt-get upgrade -y;

        sudo apt-get dist-upgrade -y;
}

clean() {

	sudo apt-get autoremove -y;
	check_exit_status

	sudo apt-get autoclean -y;
	check_exit_status

	sudo apt-get install -y locate;
	sudo updatedb;
	check_exit_status
}

exit_update() {

	echo
	echo "--------------------"
	echo "- Update Complete! -"
	echo "--------------------"
	echo
	
}


OS=$(lsb_release -si)
ARCH=$(uname -m | sed 's/x86_//;s/i[3-6]86/32/')
VER=$(lsb_release -sr)

if [ $OS != "Ubuntu" ]; then
    echo "The Tools distro is only installable on Ubuntu operating systems at this time."
    exit 1
fi

if [ $ARCH != "64" ]; then
    echoerror "The Tools distro is only installable on a 64-bit architecture at this time."
    exit 2
fi

if [ $VER != "20.04" ]; then
    echo "The Tools distro is only installable on Ubuntu 20.04 at this time."
    exit 3
fi

if [ `whoami` != "root" ]; then
    echo "The Tools installation/upgrade script must run as root."
    exit 3
fi

if [ "$SUDO_USER" = "" ]; then
    echoe "The SUDO_USER variable doesn't seem to be set"
    exit 4
fi

apt_tools()  {
	sudo apt-get install python3-pip -y; 
        sudo snap install pycdc 
        sudo apt install openjdk-11-jdk -y
	check_exit_status

INSTALL_PKGS="xterm
    vbindiff
    libssl-dev
    swig
    curl
    cmake
    libboost-all-dev
    wxhexeditor
    feh
    libffi-dev
    binutils
    curl
    exfat-utils
    stunnel4
    imagemagick
    gdb-minimal
    firefox
    xmlstarlet
    inspircd
    epic5
    tor
    torsocks
    pdftk
    clamav-daemon
    ltrace
    strace
    inetsim
    openssh-client
    openssh-server
    foremost
    ngrep
    unhide
    tcpdump
    default-jre
    tcpick
    radare2
    p7zip-full
    upx-ucl
    rhino
    python-crypto
    ssdeep
    libimage-exiftool-perl
    scalpel
    liblzma-dev
    lame
    ibus
    libgif-dev
    libjpeg-turbo8
    libjpeg-turbo8-dev
    libgtk2.0-0:i386
    libxxf86vm1:i386
    libsm6:i386
    lib32stdc++6
    gtk2-engines:i386
    gtk2-engines-*:i386
    libcanberra-gtk-module:i386
    libxslt1-dev
    libxml2-dev
    zlib1g-dev
    libyaml-dev
    bundler
    build-essential
    python
    python-dev
    automake
    python3-pip
    ruby
    ruby-dev
    git
    subversion
    mercurial
    bundler
    unrar
    dos2unix
    tcpxtract
    libsqlite3-dev
    libncurses5:i386
    automake
    libmagic-dev
    libtool
    bison
    flex
    libncurses5-dev
    python-setuptools
    python-magic
    libpcre3
    libpcre3-dev
    libpcre++-dev
    automake
    openssl
    libzmq3-dev
    libc6-dev-i386
    usbmount
    python-numpy
    python-tk
    python-pil
    libfuzzy-dev
    graphviz
    rsakeyfind
    aeskeyfind
    nginx
    ruby-gtk2
    libjavassist-java
    tcpflow
    geany
    unicode 
    qpdf
    pdfresurrect
    sysdig
    yara
    libyara3
    libyara-dev
    yara
    python-pyasn1
    python-capstone
    mitmproxy
    libemail-outlook-message-perl
    libmozjs-52-0
    libmozjs-52-dev
    libolecf-utils
    python-simplejson
    scite
    netcat
    pev
    graphviz-dev
    libqt5xmlpatterns5-dev
    qt5-default
    libqt5svg5-dev
    python-bs4
    python-wxgtk3.0"
for i in $INSTALL_PKGS; do
  sudo apt-get install -y $i
  check_exit_status
done
}


install_network_miner() {
	sudo apt-get install -y libmono-system-windows-forms4.0-cil
	sudo apt-get install -y libmono-system-web4.0-cil
	wget www.netresec.com/?download=NetworkMiner -O /tmp/nm.zip
	sudo unzip /tmp/nm.zip -d /home/$SUDO_USER/Tools/
	cd /home/$SUDO_USER/Tools/NetworkMiner*
	sudo chmod +x NetworkMiner.exe
	sudo chmod -R go+w AssembledFiles/
	sudo chmod -R go+w Captures/
	
	cat > /usr/bin/networkminer <<-EOF
	#!/bin/bash
	mono /home/$SUDO_USER/Tools/NetworkMiner_2-1-1/NetworkMiner.exe
	EOF
	
	chmod +x /usr/bin/networkminer
	check_exit_status
	cd ..
}

install_pip2() {
	curl https://bootstrap.pypa.io/get-pip.py --output get-pip.py
	sudo python2 get-pip.py
	rm get-pip.py
	check_exit_status
}

pip2_tools() {

PIP_PKGS="oletools
    xortool
    jsbeautifier
    ioc_writer
    cybox
    pype32
    mwcp
    requests
    balbuzard
    markerlib
    pdns
    peepdf
    distorm3
    officeparser
    html2text
    yara-python
    androguard
    androwarn
    officedissector
    pefile
    poster
    iocparser
    feedparser
    fuzzywuzzy
    scikit-learn
    python-Levenshtein"

for i in $PIP_PKGS; do
  sudo pip install $i
  check_exit_status
done

}


install_gems() {

PKGS="passivedns-client
    origami
    pedump"

for i in $PKGS; do
  sudo gem install $i
  check_exit_status
done
}

install_burp() {
        curl "https://portswigger.net/burp/releases/download?product=community&version=2020.4.1&type=Linux" --output burp.sh
        chmod +x burp.sh
        yes "" | ./burp.sh -c

}


pip3_tools() {
	pip3 install pefile pbkdf2 javaobj-py3 pycrypto androguard yara-python passivedns-client origami pedump
	pip3 install --upgrade malwareconfig
	check_exit_status
}




download_git() {

chmod +x /home/$SUDO_USER/RE-Toolkit/Tools/Other_Tools/densityscout && check_exit_status && chmod +x /home/$SUDO_USER/RE-Toolkit/Tools/Other_Tools/bytehist && check_exit_status
cd  /home/$SUDO_USER/RE-Toolkit/Tools/peframe && yes "" | sudo bash install.sh && check_exit_status
apt-get install autoreconf && cd  /home/$SUDO_USER/RE-Toolkit/Tools/udis86 && ./autogen.sh && ./configure && make && sudo make install && check_exit_status
apt-get install /home/$SUDO_USER/RE-Toolkit/Tools/Other_Tools/libpoppler90_0.80.0-0ubuntu1.1_amd64.deb -y && check_exit_status
apt-get install /home/$SUDO_USER/RE-Toolkit/Tools/Other_Tools/xpdf_3.04-13ubuntu4_amd64.deb -y && check_exit_status
cd  /home/$SUDO_USER/RE-Toolkit/Tools/libemu && autoreconf -v -i && ./configure && sudo make install && check_exit_status
cd  /home/$SUDO_USER/RE-Toolkit/Tools/nsrllookup && cmake . && make && sudo make install && check_exit_status
cd  /home/$SUDO_USER/RE-Toolkit/Tools/VirusTotalApi && pip install -r requirements.txt && python setup.py build && sudo python setup.py install && check_exit_status
cd  /home/$SUDO_USER/RE-Toolkit/Tools/disass && sudo python setup.py install && check_exit_status
cd  /home/$SUDO_USER/RE-Toolkit/Tools/edb-debugger && mkdir build && cd build && cmake -DCMAKE_INSTALL_PREFIX=/usr/local/ .. && make && sudo make install && check_exit_status
dpkg -i  /home/$SUDO_USER/RE-Toolkit/Tools/Other_Tools/elfparser_x86_64_1.4.0.deb && check_exit_status
cd  /home/$SUDO_USER/RE-Toolkit/Tools/maltrieve && pip install requests==2.14.2 && sudo pip install -e . && check_exit_status
chmod +x /home/$SUDO_USER/RE-Toolkit/Tools/Other_Tools/floss && sudo cp /home/$SUDO_USER/RE-Toolkit/Tools/Other_Tools/floss /bin/ && check_exit_status
cd  /home/$SUDO_USER/RE-Toolkit/Tools/katoolin3 && ./install.sh && printf '0\n1\n20\n22\n7\n11\n13\n14\n9\n' | sudo katoolin3 && check_exit_status
python3 -m pip install ciphey --upgrade && check_exit_status && 
# sudo DEBIAN_FRONTEND=noninteractive apt install -y wireshark && check_exit_status
cd /home/$SUDO_USER/RE-Toolkit/Tools && wget https://ghidra-sre.org/ghidra_9.1.2_PUBLIC_20200212.zip && unzip ghidra_9.1.2_PUBLIC_20200212.zip && echo "alias ghidra='/home/$SUDO_USER/RE-Toolkit/Tools/ghidra_9.1.2_PUBLIC/ghidraRun'" >> ~/.bashrc && check_exit_status


}


exit_install() {

	echo
	echo "--------------------"
	echo "- Install Complete! -"
	echo "--------------------"
	echo
	exit
}

greeting
update
clean
exit_update
apt_tools
install_network_miner
install_pip2
pip2_tools
install_burp
install_gems
download_git
pip3_tools
check_exit_status
exit_install
