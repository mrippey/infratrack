"""
Script: sectrailsapi

Utilize SecurityTrails API for IP and Domain lookups.

"""

import os
from httpx import get
import httpx
from rich.console import Console
from dotenv import load_dotenv
from error import StandardApiErrorMessage


load_dotenv()
console = Console()

SECTRAILS_API = os.getenv("SEC_TRAILS_KEY")


class SecurityTrailsLookup():

    def __init__(self):
        self.sectrails_key = SECTRAILS_API
        self.sectrails_api_endpoint = 'https://api.securitytrails.com/v1/'

    def _request_api(self, rsrc):
        headers = {
            'APIKEY': self.sectrails_key,
            'Content-Type': 'application/json',
        }

        try:

            response = get(f"{self.sectrails_api_endpoint}/{rsrc}", headers=headers)
            response.raise_for_status()

        except (httpx.HTTPError, httpx.ConnectTimeout) as exc:
     
            raise StandardApiErrorMessage(
                "There may be an error in your API URL"
            ) from exc
            
        return response.json()

    def get_domain_details(self, target):
        api_endpoint_domain = f'domain/{target}'
        response = self._request_api(api_endpoint_domain)

        if response.get('current_dns'):
            first_seen = response['current_dns']['a']['first_seen']
            ip = response['current_dns']['a']['values'][0]['ip']
            hostname_org = response['current_dns']['mx']['values'][0]['hostname_organization']
            nameserver = response['current_dns']['ns']['values'][0]['nameserver']
            nameserver_org = response['current_dns']['ns']['values'][0]['nameserver_organization']

            return f"first_seen: {first_seen}, ip: {ip}, hostname: {hostname_org}, NS: {nameserver}, NS Org: {nameserver_org}"
          
    def get_ip_details(self, target):
        api_endpoint_ip = f'ips/nearby/{target}'
        response = self._request_api(api_endpoint_ip)

        if response.get('blocks'):
            nearby_hosts = []
            for block in response['blocks']:
                nearby_hosts += block['hostnames']

            return nearby_hosts


st = SecurityTrailsLookup()
st_domain = st.get_ip_details('51.222.103.8')
print(st_domain)
