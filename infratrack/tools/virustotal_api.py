"""
Script: virustotal_api 

This script combines the IP address and domain lookups into one convenient location.

"""

import os
from httpx import get
import httpx
from rich.console import Console
from dotenv import load_dotenv
from tools.error import StandardApiErrorMessage


load_dotenv()
console = Console()

VIRUSTOTAL_API = os.getenv("VT_API_KEY")


class VirusTotalApiLookup:
    """VT lookup class
    """    
    def __init__(self):
        self.vt_api_key = VIRUSTOTAL_API
        self.base_url = "https://www.virustotal.com/api/v3/"

    def _request_api(self, res):
        headers = {"x-apikey": VIRUSTOTAL_API}

        try:
            response = get(f"{self.base_url}{res}", headers=headers)
            response.raise_for_status()

        except (httpx.HTTPError, httpx.ConnectTimeout) as exc:
     
            raise StandardApiErrorMessage(
                "There may be an error in your API URL"
            ) from exc

        return response.json()

    def get_hist_ssl_certs(self, target):
        """VT get historical SSL certificate info"""
        url_resrc = f'ip_addresses/{target}/historical_ssl_certificates'
        response = self._request_api(url_resrc)

        if response.get('data'):
            data = response['meta']
            count = data['count']
            if count >= 1:
                return f'[red]{str(count)} [white]historical certificates associated with {target}'
            
            return f'No historical certs found for {target}'

    def get_ip_resolutions(self, target):
        """VT get IP resolutions"""

        url_resrc = f"ip_addresses/{target}/resolutions"
        response = self._request_api(url_resrc)
        if not response.get('data'):
            return f"{target} is clean."
        resolutions = response['data']
        return [resolution['attributes']['host_name'] for resolution in resolutions]


    def get_ip_info(self, target):
        url_resrc = f'ip_addresses/{target}'
        response = self._request_api(url_resrc)
        if response.get('data'):
            data = response['data']
            attrs = data['attributes']
            last_analysis = attrs['last_analysis_stats']
            is_malicious = last_analysis['malicious']
            
            if is_malicious >= 1:
                return f"{target} [white]was identified as malicious by [red]{str(is_malicious)} vendors"
            else:
          
                return f"{target} is [green]clean"

    def get_domain_info(self,  target):
        url_resrc = f'domains/{target}'
        response = self._request_api(url_resrc)
        if response.get('data'):
            data = response['data']
            attrs = data['attributes']
            last_analysis = attrs['last_analysis_stats']
            is_malicious = last_analysis['malicious']
            
            if is_malicious == 1:
                return f"{target} [white]was identified as malicious by [red]{str(is_malicious)} vendors"
          
            return f"{target} is clean"

    def get_domain_comm_files(self, target):
        """VT get communicating files"""
        url_resrc = f'domains/{target}/communicating_files'
        response = self._request_api(url_resrc)

        if response.get('meta'):
            comm_files = response['meta']['count']
            return f'[red]{str(comm_files)} [white]files detected communicating with {target}'
        else:
            return f'No files communicating with {target}'


