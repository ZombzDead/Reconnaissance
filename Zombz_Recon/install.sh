#!/usr/bin/bash

#COLORS
GREEN="\033[1;32m"
BLUE="\e[34m"
MAGENTA="\e[95m"
CYAN="\e[36m"
BOLD="\e[1m"
NORMAL="\e[0m"

printf "${BOLD}${GREEN}!! Hang onto your Butts !!\n"

printf "${BOLD}${BOLD}${MAGENTA}Installing Repositories\n${NORMAL}"
cd ~/opt/tools/Zombz_Recon
mkdir Repositories && cd Repositories

printf "${BOLD}${BOLD}${MAGENTA}Installing DNS Reconnaissance Tools\n${NORMAL}"
sudo apt install -y massdns

git clone https://github.com/nmmapper/dnsdumpster.git && cd dnsdumpster
sudo pip3 install -r requirements.txt
cd ..

printf "${BOLD}${CYAN}Trufflehog - Git Repo Pilfer\n\n${NORMAL}"
sudo apt install -y trufflehog

go install github.com/koenrh/s3enum@v1

printf "${BOLD}${BOLD}${MAGENTA}Installing Web Gathering Tools\n${NORMAL}"
sudo apt install -y html2text arjun nuclei cmseek hakrawler dirsearch

printf "${BOLD}${BOLD}${MAGENTA}Installing Cloud Enumeration Tools\n${NORMAL}"
sudo apt install -y cloud-enum s3scanner 

printf "${BOLD}${CYAN}Installing Reconnaissance Tools\n${NORMAL}"
sudo apt install -y emailharvester mxcheck

printf "${BOLD}${CYAN}Screenshot Tool\n${NORMAL}"
sudo apt install -y imagemagick

apt-get -y autoremove

sleep 10s

## sudo reboot