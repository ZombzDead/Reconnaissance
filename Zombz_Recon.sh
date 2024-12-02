#!/bin/bash
actualDir=$(pwd)

dnsDictionary="/opt/tools/SecLists/Discovery/DNS/dns-Jhaddix.txt"
dictionary="/opt/tools/SecLists/Discovery/Web-Content/dirsearch.txt"
excludeStatus="404,403,401,503"
burpCollaborator="https://recon.bc.nhbrsec.com"

#COLORS
RED="\e[31m"
GREEN="\033[1;32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[95m"
CYAN="\e[36m"
BOLD="\e[1m"
NORMAL="\e[0m"

##############################################
############### PASSIVE RECON ################
##############################################
passive_recon(){
	printf "\n"
	printf "${BOLD}${GREEN}[*] STARTING FOOTPRINTING${NORMAL}\n\n"
	printf "${BOLD}${GREEN}[*] TARGET URL:${YELLOW} $domain ${NORMAL}\n"
	ip_adress=$(dig +short $domain)
	printf "${BOLD}${GREEN}[*] TARGET IP ADDRESS:\n ${YELLOW} $ip_adress ${NORMAL}\n\n"
	
	domain=$1
	domainName="https://"$domain
	company=$(echo $domain | awk -F[.] '{print $1}')
	
	cd Pawns
	
	if [ -d $domain ]; then rm -Rf $domain; fi
	mkdir Passive_Recon	
	
	cd Passive_Recon
	
	printf "\n${BOLD}${GREEN}[+] Checking if the target is alive...${NORMAL}\n"
	if ping -c 1 -W 1 "$domain" > ping_results.txt; 
	then
		printf "\n${BOLD}${YELLOW}$domain${NORMAL} is alive and well!${NORMAL}\n\n"
	else
		if [ $mode == "more" ]
		then
			printf "\n${BOLD}${YELLOW}$domain${RED} is dead, unfortunately.${NORMAL}\n\n"
			exit 1
		fi	
	fi
	
	printf "\n${BOLD}${GREEN}[+] Whois Lookup${NORMAL}\n"
	printf "${NORMAL}${CYAN}Searching domain name details, contact details of domain owner, domain name servers, netRange, domain dates, expiry records, records last updated...${NORMAL}\n\n"
	whois $domain | grep '${BOLD}$Domain\|${BOLD}$Registry\|Registrar\|Updated\|Creation\|Registrant\|Name Server\|DNSSEC:\|Status\|Whois Server\|Admin\|Tech' | grep -v 'the Data in VeriSign Global Registry' | tee whois.txt

	printf "\n${BOLD}${GREEN}[+] Nslookup ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Searching DNS Queries...${NORMAL}\n\n"
	nslookup $domain | tee nslookup.txt
	
	printf "\n${BOLD}${GREEN}[+] DNS Recon ${NORMAL}\n"
	printf "${NORMAL}${CYAN}DNS Reconnaissance...${NORMAL}\n\n"
	sudo dnsrecon -d $domain | tee dnsrecon.txt

	printf "\n${BOLD}${GREEN}[+] DNS Enum ${NORMAL}\n"
	printf "${NORMAL}${CYAN}DNS Enumeration...${NORMAL}\n\n"
	dnsenum $domain | tee dnsenum.txt

	printf "\n${BOLD}${GREEN}[+] DNSDumpster Search ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Searching domains to discover hosts related to the domain ${NORMAL}\n\n"
	python3 ~/opt/tools/Zombz_Recon/Repositories/dnsdumpster/dnsdumpster.py -d $domain | tee dnsdumpster.txt | convert label:@- dnsdumpster.png

	printf "\n${GREEN}[+] MXRecord Lookup ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Checking SPF and DMARC record...${NORMAL}\n\n"
	mailspoof -d $domain | tee mxrecord.txt
	
	printf "\n${BOLD}${GREEN}[+] WhatWeb ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Searching platform, type of script, google analytics, web server platform, IP address, country, server headers, cookies...${NORMAL}\n\n"
	whatweb $domain | tee whatweb.csv
	
	printf "\n${BOLD}${GREEN}[+] SSL Scan ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Collecting SSL/TLS information...${NORMAL}\n\n"
	sslscan -d $domain | tee ssl.txt

	printf "\n${BOLD}${GREEN}[+] Security Header Check ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Collecting Security Headers...${NORMAL}\n\n"
	shcheck.py https://$domain -i -x | tee shcheck_https.txt
	shcheck.py http://$domain -i -x | tee shcheck_http.txt

	printf "\n${BOLD}${GREEN}[+] CMSeek ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Collecting CMS Detection & Exploitation Suite...${NORMAL}\n\n"
	python3 /opt/tools/Zombz_Recon/Repositories/CMSeeK/cmseek.py -u $domain --follow-redirect 
	
	printf "\n${BOLD}${GREEN}[+] Shodan Query ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Collecting Organization Information from Shodan...${NORMAL}\n\n"
	curl -X GET "https://api.shodan.io/$domain?key={Input_key}" > shodan_org.txt

	printf "\n${BOLD}${GREEN}[+] TheHarvester ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Searching emails, subdomains, hosts, employee names...${NORMAL}\n\n"
	theHarvester -d $domain -b all -l 500 | tee theharvester.txt
	
	printf "\n${BOLD}${GREEN}[+] CloudEnum ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Searching public resources in AWS, Azure, and Google Cloud....${NORMAL}\n\n"
	~/opt/tools/Zombz_Recon/Repositories/cloud_enum/cloud_enum.py -k $domain | tee CloudEnum.txt
		
	printf "\n${BOLD}${GREEN}[+] GitDorker ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Searching interesting data on GitHub...${NORMAL}\n\n"
	domainName="https://"$domain
	python3 ~/opt/tools/Zombz_Recon/Repositories/GitDorker/GitDorker.py -t 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 -d ~/opt/tools/Zombz_Recon/Repositories/GitDorker/Dorks/alldorksv3 -q $domain -o dorks.txt

    printf "\n${BOLD}${GREEN}[+] Sublist3r ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Enumerates Subdomsin of websites utilizing OSINT...${NORMAL}\n\n"
	sublist3r -d $domain | tee sud_domains.txt
	
	cd $actualDir
}

##############################################
############### ACTIVE RECON #################
##############################################
active_recon(){
	printf "\n"
	printf "${BOLD}${GREEN}[*] STARTING FINGERPRINTING${NORMAL}\n\n"
	printf "${BOLD}${GREEN}[*] TARGET URL:${YELLOW} $domain ${NORMAL}\n"
	ip_adress=$(dig +short $domain)
	printf "${BOLD}${GREEN}[*] TARGET IP ADDRESS:${YELLOW} $ip_adress ${NORMAL}\n\n"
	
	domain=$1
	domainName="https://"$domain
	
	cd Pawns
	
	if [ -d $domain ]; then rm -Rf $domain; fi
	mkdir Active_Recon
	
	cd Active_Recon
	
	printf "\n${GREEN}[+] Nmap ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Searching open ports...${NORMAL}\n\n"
	nmap -p- --open -T5 -v -n $domain -oN nmap.txt

	printf "\n${GREEN}[+] Arp Scan ${NORMAL}\n"
	printf "${NORMAL}${CYAN}ARP Scanning beginning...${NORMAL}\n\n"
	arp-scan -l | tee arp_scan.txt

	printf "\n${GREEN}[+] DNSEnum ${NORMAL}\n"
	printf "${NORMAL}${CYAN}DNS Enumeration Running...${NORMAL}\n\n"
	dnsenum $domain | tee dnsenum.txt

	printf "\n${GREEN}[+] DNSRecon ${NORMAL}\n"
	printf "${NORMAL}${CYAN}DNS Reconnaissance Initiated...${NORMAL}\n\n"
	dnsrecon -d $domain -t axfr | tee dnsrecon.txt
	
	printf "\n${GREEN}[+] EyeWitness Scan ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Conducting Eyewitness Scan Against Nessus Files${NORMAL}\n\n"
	python3 ~/opt/tools/eyewitness/Python/Eyewitness.py -x /opt/engagement/Nessus/*.nessus
	
	cd $actualDir
}

##############################################
############### ALL MODES ####################
##############################################
all(){
	passive_recon $domain
	active_recon $domain
	web_scanning $domain
}

##############################################
############### ALL RECON ####################
##############################################
all_recon(){
	passive_recon
	active_recon
}

##############################################
############### Web Scanning ##############
##############################################
web_scanning(){
	printf "\n"
	printf "${BOLD}${GREEN}[*] STARTING WEB SCAN${NORMAL}\n\n"
	printf "${BOLD}${GREEN}[*] TARGET URL:${YELLOW} $domain ${NORMAL}\n"
	ip_adress=$(dig +short $domain)
	printf "${BOLD}${GREEN}[*] TARGET IP ADDRESS:${YELLOW} $ip_adress ${NORMAL}\n\n"
	
	domain=$domain
	domainName="https://"$domain
	
	cd Pawns
	
	if [ -d $domain ]; then rm -Rf $domain; fi
	mkdir Web_Scan
	
	cd Web_Scan
	
	printf "\n${GREEN}[+] Hakrawler & gau ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Gathering URLs and JavaSript file locations...${NORMAL}\n\n"
	echo $domain | hakrawler | tee -a paths.csv
	gau $domain >> paths.csv
	sort -u paths.csv -o paths.csv
	
	printf "\n${GREEN}[+] Arjun ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Finding query parameters for URL endpoints....${NORMAL}\n\n"
	arjun -u https://$domain -oT parameters.csv
	
	printf "\n${GREEN}[+] DirSearch ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Searching interesting directories and files...${NORMAL}\n\n"
	sudo dirsearch -u $domain --deep-recursive --random-agent --exclude-status "$excludeStatus" -w "$dictionary" -o dirsearch.csv
	
	printf "\n${GREEN}[+] Web Scan: Multiples vulnerabilities${NORMAL}\n"
	printf "${NORMAL}${CYAN}Running multiple templates to discover vulnerabilities...${NORMAL}\n\n"
	nuclei -u $domain -t ~/opt/tools/Zombz_Recon/Repositories/nuclei-templates/ -severity low,medium,high,critical -silent -o mutiple_vulnerabilities.txt
	
	cd $actualDir
}

##############################################
############### WILDCARD RECON ###############
##############################################
wildcard_recon(){
	printf "\n"
	printf "${BOLD}${GREEN}[*] STARTING SUBDOMAIN ENUMERATION${NORMAL}\n\n"
	printf "${BOLD}${GREEN}[*] WILDCARD:${YELLOW} *.$wildcard ${NORMAL}\n"
	
	cd Pawns

	if [ -d subdomains ]; then rm -Rf subdomains; fi
	mkdir Wildcard_Recon
	cd Wildcard_Recon
	
	printf "\n${GREEN}[+] Subfinder ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Searching subdomains...${NORMAL}\n\n"
	subfinder -silent -d $wildcard -o subdomains.txt
	
	printf "\n${GREEN}[+] Amass ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Searching subdomains with bruteforce...${NORMAL}\n\n"	
	amass enum -d $wildcard -w "$dnsDictionary" -o bruteforce.txt
	cat bruteforce.txt >> subdomains.txt
	rm bruteforce.txt
	sort -u subdomains.txt -o subdomains.txt
	
	printf "\n${GREEN}[+] Httpx ${NORMAL}\n"
	printf "${NORMAL}${CYAN}Checking alive subdomains...${NORMAL}\n\n"
	httpx -l subdomains.txt -silent -o alive.txt
	
	#Removing http/https word from alive.txt
	cp alive.txt alive_subdomains.txt
	sed -i 's#^http://##; s#/score/$##' alive_subdomains.txt
	sed -i 's#^https://##; s#/score/$##' alive_subdomains.txt
	sort -u alive_subdomains.txt -o alive_subdomains.txt
	
	cat alive_subdomains.txt | python3 -c "import sys; import json; print (json.dumps({'domains':list(sys.stdin)}))" > alive.json
	cat subdomains.txt | python3 -c "import sys; import json; print (json.dumps({'domains':list(sys.stdin)}))" > subdomains.json
	
	sed 's/ \+/,/g' alive_subdomains.txt > alive.csv
	sed 's/ \+/,/g' subdomains.txt > subdomains.csv
	
	mode="more"
	
	for domain in $(cat alive_subdomains.txt);do
		all $domain $more
	done
	
	cd $actualDir
}

##############################################
############### HELP SECTION #################
##############################################

help(){
	printf "\n"
	printf "${BOLD}${GREEN}USAGE${NORMAL}\n"
	printf "$0 [-d domain.com] [-w domain.com] [-l listdomains.txt]"
	printf "\n           	      [-a] [-p] [-x] [-r] [-ws] [-m] [-n] [-h] \n\n"
	printf "${BOLD}${GREEN}TARGET OPTIONS${NORMAL}\n"
	printf "   -d domain.com     Target domain\n"
	printf "   -w domain.com     Wildcard domain\n"
	printf "   -l list.txt       Target list\n"
	printf " \n"
	printf "${BOLD}${GREEN}MODE OPTIONS${NORMAL}\n"
	printf "   -a, --all         All mode - Full scan with full target recognition and vulnerability scanning\n"
	printf "   -p, --passive     Passive reconnaissance (Footprinting) - Performs only passive recon with multiple tools\n"
	printf "   -x, --active      Active reconnaissance (Fingerprinting) - Performs only active recon with multiple tools\n"
	printf "   -r, --recon       Reconnaissance - Perform active and passive reconnaissance\n"
	printf "   -ws, --web_scan    Web Scanning - Check multiple vulnerabilities in the domain/list domains\n"
	printf " \n"
	printf "${BOLD}${GREEN}EXTRA OPTIONS${NORMAL}\n"
	printf "   -h, --help                Help - Show this help\n"
	printf " \n"
	printf "${BOLD}${GREEN}EXAMPLES${NORMAL}\n"
	printf " ${CYAN}All:${NORMAL}\n"
	printf " ./Zombz_Recon.sh -d domain.com -a\n"
	printf " \n"
	printf " ${CYAN}Passive reconnaissance to a list of domains:${NORMAL}\n"
	printf " ./Zombz_Recon.sh -l domainlist.txt -p\n"
	printf " \n"
	printf " ${CYAN}Active reconnaissance to a domain:${NORMAL}\n"
	printf " ./Zombz_Recon.sh -d domain.com -x\n"
	printf " \n"
	printf " ${CYAN}Full reconnaissance:${NORMAL}\n"
	printf " ./Zombz_Recon.sh -d domain.com -r\n"
	printf " \n"
	printf " ${CYAN}Full reconnaissance and web scanning:${NORMAL}\n"
	printf " ./Zombz_Recon.sh -d domain.com -r -ws\n"
	printf " \n"
	printf " ${CYAN}Full reconnaissance and vulnerabilities scanning to a wildcard:${NORMAL}\n"
	printf " ./Zombz_Recon.sh -w domain.com \n"
	printf " \n"

}

##############################################
###############LAUNCH SCRIPT##################
##############################################

usage(){
	printf "\n"
	printf "Usage: $0 [-d domain.com] [-w domain.com] [-l listdomains.txt]"
	printf "\n           	      [-a] [-p] [-x] [-r] [-ws] [-m] [-n] [-h] \n\n"
  exit 2
}

printf "${BOLD}${GREEN}"
figlet -f smmono9 "!! Zombz Recon !!"
printf "${BOLD}${MAGENTA}They locked down their fortress - with locks!"
printf "\n"

PARSED_ARGUMENTS=$(getopt -a -n recon -o "d:w:l:apxrvmnh" --long "domain:,wildcard:,list:,all,passive,active,recon,web_scan,help" -- "$@")
VALID_ARGUMENTS=$?

if [ $VALID_ARGUMENTS != "0" ]; 
then
  usage
fi

if [ $# == 0 ]
then
    printf "${RED}[!] No arguments detected \n${NORMAL}"
    exit 1
fi

eval set -- "$PARSED_ARGUMENTS"

mode_recon=0
vulnerabilitiesMode=false


while :
do
    case "$1" in	    
		'-d' | '--domain')
			domain=$2
			shift
			shift
			continue
		;;
		'-w' | '--wildcard')
			wildcard=$2
			shift
			shift
			continue
		;;
		'-l' | '--list')
			domainList=$2
			shift
			shift
			continue
		;;
		'-a' | '--all')
			mode_recon=1
			shift
			continue
		;;
		'-p' | '--passive')
			mode_recon=2
			shift
			continue
		;;
		'-x' | '--active')
			mode_recon=3
			shift
			continue
		;;
		'-r' | '--recon')
			mode_recon=4
			shift
			continue
		;;
		'-ws' | '--web_scan')
			mode_recon=5
			shift
			continue
		;;
		'-h' | '--help')
			help
			exit
		;;
	        '--')
			shift
			break
	        ;;
	        *) 
        	    	printf "${RED}[!] Unexpected option: $1 - this should not happen. \n${NORMAL}"
       			usage 
       		;;
    esac
done

if [ -z "$domain" ] && [ -z "$wildcard" ] && [ -z "$domainList" ]
then
    printf "${RED}[!] Please specify a domain (-d | --domain), a wildcard (-w | --wildcard) or a list of domains(-l | --list) \n${NORMAL}"
    exit 1
fi

if [ ! -d Pawns ]; 
then 
	mkdir Pawns 
fi

if [ ! -z "$wildcard" ] && [ $mode_recon != 5 ]
then
	wildcard_recon $wildcard
	exit 1
fi

case $mode_recon in
	0)
		if [ -z "$domainList" ]
		then
			if [ $vulnerabilitiesMode == true ]
			then
				vulnerabilities $domain $notifyMode
			fi
		else
			if [ $vulnerabilitiesMode == true ]
			then
				for domain in $(cat $domainList);do
					vulnerabilities $domain $notifyMode
				done
			fi	
		fi
	;;
	1)
		if [ -z "$domainList" ]
		then
			all $domain $notifyMode
		else
			for domain in $(cat $domainList);do
				all $domain $notifyMode
			done
		fi
	;;
	2)
		if [ -z "$domainList" ]
		then
			passive_recon $domain $notifyMode $vulnerabilitiesMode
		else
			for domain in $(cat $domainList);do
				passive_recon $domain $notifyMode $vulnerabilitiesMode
			done
		fi
	;;
	3)
		if [ -z "$domainList" ]
		then
			active_recon $domain $notifyMode $vulnerabilitiesMode
		else
			for domain in $(cat $domainList);do
				active_recon $domain $notifyMode $vulnerabilitiesMode
			done
		fi
	;;
	4)
		if [ -z "$domainList" ]
		then
			all_recon $domain $notifyMode 
		else
			for domain in $(cat $domainList);do
				all_recon $domain $notifyMode 
			done
		fi
	;;
        *)
            help
            exit 1
    ;;
esac		
						
