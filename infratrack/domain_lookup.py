"""
Script: domain_lookup

This script provides the results for a domain lookup using VirusTotal,
RiskIQ, and WhoIs
"""
import os
import time
from dotenv import load_dotenv
import whois
from httpx import get
import httpx
from rich.console import Console
from rich import table
from core.logs import LOG
from tools.error import StandardApiErrorMessage
from connect_mongodb import insert_results_to_mongodb
from tools.virustotal_api import VirusTotalApiLookup
from tools.rich_tables import ResultsTable

load_dotenv()
console = Console()


class DomainLookup:
    """_summary_ - DomainSummary class"""

    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.vt_api_key = os.getenv("VT_API_KEY")
        self.vt_api_key_header = {"x-apikey": self.vt_api_key}
        # VirusTotal API requests
        self.vt_api_basic_domain = (
            f"https://www.virustotal.com/api/v3/domains/{target_domain}"
        )
        self.vt_domain_commfiles = f"https://www.virustotal.com/api/v3/domains/{target_domain}/communicating_files"
        self.pdns_resolutions = []
        self.first_seen = ''
        self.last_seen = ''
        self.vt_api = VirusTotalApiLookup()
        self.domain_table = ResultsTable()

    def get_vt_domain_info(self, domain):
        return self.vt_api.get_domain_info(self.target_domain)

    def get_vt_domain_comm_files(self, domain):
        return self.vt_api.get_domain_comm_files(self.target_domain)

    def get_riskiq_api_results(self, target_domain: str):
        """Get RiskIQ API results for domain

        Args:
            target_domain (str): domain to lookup

        Raises:
            StandardApiErrorMessage
        """        
        riskiq_user = os.getenv("RISKIQ_USER")
        riskiq_apikey = os.getenv("RISKIQ_KEY")
        auth = (riskiq_user, riskiq_apikey)
        data = {"query": self.target_domain}
        LOG.debug("RiskIQ API GET request for %s", self.target_domain)
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
        for items in riq_api_results["results"]:
            self.pdns_resolutions = items["resolve"]
            self.first_seen = riq_api_results["firstSeen"]
            self.last_seen = riq_api_results["lastSeen"]

    def run(self):
        """_summary_ - Run the main code"""
        try:
            self.build_db_document()
        except whois.parser.PywhoisError as err:
            LOG.critical(
                "Error in WhoIs, a domain name not aligning with the RFCs may have been submitted."
            )
            print(f"WhoIs -- {err}")

        except (httpx.HTTPError, httpx.ConnectTimeout) as exc:
            LOG.critical("Error in API URL")
            raise StandardApiErrorMessage(
                "There may be an error in your API URL"
            ) from exc

    def build_db_document(self):
        """ Combines all data from API's and WhoIs lookups"""

        LOG.info("Starting domain_lkup_summary.py...")

        console.print(f"Querying API services for {self.target_domain}...")
        self.get_riskiq_api_results(self.target_domain)
        domain_info = whois.whois(self.target_domain)
        whois_country = whois.whois(str(self.pdns_resolutions))
        self.domain_registrar = domain_info.registrar or 'Not available'
        self.domain_country = whois_country.country or 'Not Available'
        self.nameservers = domain_info.name_servers or 'Not Available'
        console.print(self.create_table_from_output())
        insert_results_to_mongodb(
                str(self.pdns_resolutions),
                self.target_domain,
                self.first_seen,
                self.domain_registrar,
                self.nameservers,
                self.domain_country,
            )

    def create_table_from_output(self) -> table:
        """Create table of query results for easy reading in CLI

        Returns:
            Rich vertical table
        """

        return self.domain_table.build_table_domain(

            resolve=str(self.pdns_resolutions),
            country=self.domain_country,
            first_seen=str(self.first_seen),
            last_seen=str(self.last_seen),
            domain=self.target_domain,
            nameserv=str(self.nameservers) or 'Not Found',
            registrar=self.domain_registrar or 'Not Found',
            vt_domain_info=self.vt_api.get_domain_info(self.target_domain),
            vt_domain_comm_files=self.vt_api.get_domain_comm_files(self.target_domain),
            )
       