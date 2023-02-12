"""
Script: ip_address_lookup

This script provides the results for an IP lookup using VirusTotal,
RiskIQ, and WhoIs
"""
import os
import sys
import time
import ipaddress
from rich.console import Console
from dotenv import load_dotenv
import whois
from httpx import get
import httpx
from core.logs import LOG
from tools.error import StandardApiErrorMessage
from connect_mongodb import insert_results_to_mongodb
from tools.virustotal_api import VirusTotalApiLookup
from tools.rich_tables import ResultsTable

load_dotenv()
console = Console()

VIRUSTOTAL_API = os.getenv("VT_API_KEY")
GREYNOISE_API = os.getenv("GREYNOISE_API")


class IPAddressLookup:
    """_summary_ - IP address summary"""

    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.greynoise_api_url = f"https://api.greynoise.io/v3/community/{target_ip}"
        self.gn_result = {}
        self.first_seen = ""
        self.last_seen = ""
        self.vt_api = VirusTotalApiLookup()
        self.results_table = ResultsTable()

    def get_greynoise_api(self, target_ip: str) -> dict:
        """_summary_ - GreyNoise API request
        Args:
        target_ip (str): The IP address you want to investigate.
        """
        LOG.debug("GreyNoise GET request for %s", target_ip)
        headers = {"key": GREYNOISE_API}
        try:
            response = get(self.greynoise_api_url, headers=headers)
        except (httpx.HTTPError, httpx.ConnectTimeout) as exc:
            LOG.critical("Error in API URL")
            raise StandardApiErrorMessage(
                "There may be an error in your API URL"
            ) from exc

        self.gn_result = response.json()
        LOG.debug("Received a response: %s", self.gn_result)

    def ip_info(self, target_ip):
        return self.vt_api.get_ip_info(target_ip)

    def get_ip_hist_resolutions(self, target_ip):
        return self.vt_api.get_ip_resolutions(target_ip)

    def get_ip_hist_certs(self, target_ip):
        return self.vt_api.get_hist_ssl_certs(target_ip)

    def get_riskiq_api_results(self, target_ip: str):
        """Get RiskIQ API results for domain

        Args:
            target_domain (str): domain to lookup

        Raises:
            StandardApiErrorMessage
        """
        riskiq_user = os.getenv("RISKIQ_USER")
        riskiq_apikey = os.getenv("RISKIQ_KEY")
        auth = (riskiq_user, riskiq_apikey)
        data = {"query": self.target_ip}
        LOG.debug("RiskIQ API GET request for %s", self.target_ip)
        try:
            response = get(
                "https://api.riskiq.net/pt/v2/dns/passive", auth=auth, params=data
            )
            time.sleep(1)

        except (httpx.HTTPError, httpx.ConnectTimeout) as exc:
            LOG.critical("Error in API URL")
            raise StandardApiErrorMessage(
                "There may be an error in your API URL"
            ) from exc

        riq_api_results = response.json()

        LOG.debug("Received a response: %s", riq_api_results)
        for _ in riq_api_results["results"]:
            self.first_seen = riq_api_results["firstSeen"]
            self.last_seen = riq_api_results["lastSeen"]

    def run(self):
        """_summary_ -- Run the program."""
        LOG.info("Starting ip_lkup_summary.py")
        try:
            console.print(f"Querying API services for {self.target_ip}...\n")
            self.build_db_document()
        except ipaddress.AddressValueError as err:
            console.print(err, style="bold red")
            sys.exit(1)

    def build_db_document(self):
        """Combines all data from API's and WhoIs lookups"""

        LOG.info("Starting domain_lkup_summary.py...")
        self.get_riskiq_api_results(self.target_ip)

        self.get_ip_res = self.get_ip_hist_resolutions(self.target_ip)
        
        ip_whois_info = whois.whois(self.target_ip)

        if ip_whois_info.registrar is None:
            ip_whois_info.registrar = "N/A"

        ip_whois_country = ip_whois_info.country or "N/A"
        ip_whois_nameserver = ip_whois_info.nameservers or "N/A"
        console.print(self.create_table_from_output())

        insert_results_to_mongodb(
            str(self.get_ip_res),
            self.target_ip,
            self.first_seen,
            ip_whois_info.registrar or "N/A",
            ip_whois_nameserver,
            ip_whois_country,
        )

    def create_table_from_output(self):
        """_summary_ -- Combine all API output and build a table"""

        return self.results_table.build_table_ip(
            ip=self.target_ip,
            first_seen=str(self.first_seen),
            last_seen=str(self.last_seen),
            gnoise=str(self.gn_result.get("classification")),
            vt_ip_info=self.ip_info(self.target_ip),
            vt_ip_res=str(self.get_ip_res),
            vt_hist_certs=self.get_ip_hist_certs(self.target_ip),
        )
