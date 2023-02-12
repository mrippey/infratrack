""" 
Script: rich_tables

This script creates Rich vertical tables using the information from the API lookups

"""

import sys
from rich import table
from rich.box import MINIMAL
from rich.console import Console

console = Console()


class ResultsTable:
    def __init__(self):
        pass

    def build_table_ip(
        self, ip, first_seen, last_seen, gnoise, vt_ip_info, vt_ip_res, vt_hist_certs
    ):

        """_summary_ -- Combine all API output and build a table"""

        ip_summ_table = self._final_table_results()
        try:
            ip_summ_table.add_row(
                "[white]IP Summary",
                f"[white]IP:          {ip}\n"
                f"[white]First Seen:  {str(first_seen or 'N/A')}\n"
                f"[white]Last Seen:   {str(last_seen or 'N/A')}\n"
            )

            ip_summ_table.add_row(
                "[white]GreyNoise",
                f"[white]GreyNoise Report:  {gnoise}\n"
            )

            ip_summ_table.add_row(
                "[white]VirusTotal (VT)",
                f"[white]VT Score:                    {vt_ip_info}\n"
                f"[white]VT Historical Resolutions:   {vt_ip_res}\n"
                f"[white]VT Historical Certs:         {vt_hist_certs}"
            )
            print()

        except Exception:
            console.print_exception(show_locals=True)
            sys.exit(1)

        return ip_summ_table

    def build_table_domain(
        self,
        resolve,
        country,
        first_seen,
        last_seen,
        domain,
        nameserv,
        registrar,
        vt_domain_info,
        vt_domain_comm_files,
    ):

        domain_summ_table = self._final_table_results()
        try:
            domain_summ_table.add_row(
                "[white]Domain Summary",
                f"[white]IP:          {resolve}\n"
                f"[white]Country:     {country}\n"
                f"[white]First Seen:  {first_seen}\n"
                f"[white]Last Seen:   {last_seen}\n"
            )

            domain_summ_table.add_row(
                "[white]Domain Info",
                f"[white]Domain Name:     {domain}\n"
                f"[white]Name Server(s):  {nameserv or 'Not Found'}\n"
                f"[white]Registrar:       {registrar or 'Not Found'}\n"
            )

            domain_summ_table.add_row(
                "[white]VirusTotal(VT)",
                f"[white]VT Score:             {vt_domain_info}\n"
                f"[white]Communicating Files:  {vt_domain_comm_files}\n"
            )

        except Exception:
            console.print_exception(show_locals=True)
            sys.exit(1)
        print()
        return domain_summ_table

   
    def _final_table_results(self):
        result = table.Table(show_header=False, show_footer=False, box=MINIMAL)
        result.add_column()
        result.add_column(overflow="fold")
        return result
