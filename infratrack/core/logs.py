"""_summary_ --  logs.py """
import logging

LOG = logging

LOG.basicConfig(
    level=LOG.DEBUG,
    filename="/Users/m_a_t/Documents/Python_Projects/infratrack/infratrack/logs/logs.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
)
