#!/usr/bin/env python3
"""
Copyright (c) 2022 InfraTrack, Author: (https://github.com/mrippey/infratrack/)
See the file 'LICENSE' for copying permission
"""
from argparse import ArgumentParser
import sys
from shodan_censys_scan import ShodanCensysScan
from ip_address_lookup import IPAddressLookup
from domain_lookup import DomainLookup
from core.logs import LOG


def main():
    """Main function"""
    LOG.debug("Main program starting...")
    print("""
██╗███╗   ██╗███████╗██████╗  █████╗ ████████╗██████╗  █████╗  ██████╗██╗  ██╗
██║████╗  ██║██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
██║██╔██╗ ██║█████╗  ██████╔╝███████║   ██║   ██████╔╝███████║██║     █████╔╝ 
██║██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║   ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ 
██║██║ ╚████║██║     ██║  ██║██║  ██║   ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗
╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                                                                         
    """)
    parser = ArgumentParser(
        description="Adversary infrastructure tracker. Developed by Michael Rippey",
    
    )

    parser.add_argument("-hu", "--hunt", nargs="+", help="Targets to scan")
    parser.add_argument("-i", "--ipaddr", help="IP address to scan")
    parser.add_argument("-d", "--domain", help="Domain to scan")

    args = parser.parse_args()

    if args.ipaddr:
        LOG.info("Starting IP address scan...")
        ipaddr = args.ipaddr
        ip_summary = IPAddressLookup(ipaddr)
        ip_summary.run()
      
    elif args.domain:
        LOG.info("Starting domain scan...")
        domain = args.domain
        domain_summary = DomainLookup(domain)
        domain_summary.run()

    else:
        parser.print_help()
        LOG.error("Be sure you provided an argument using '--arg' followed by the appropriate target path")
        sys.exit(1)
 

if __name__ == "__main__":
    main()
