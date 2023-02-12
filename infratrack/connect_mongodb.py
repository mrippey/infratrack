""" mongoddb_connect.py """
import os
import pymongo
from pymongo.server_api import ServerApi


def insert_results_to_mongodb(ipaddr: str, domain: str, first_seen: str, reg: str, nameservr: str, country: str):
    """Take results of IP/Domain lookups and insert to MongoDB instance

    Args:
        ipaddr (str): IP to insert
        domain (str): Domain to insert
        first_seen (str): First seen time/date
        reg (str): Registrar to insert
        nameservr (str): Nameserver of domain to insert
        country (str): Country domain is hosted
    """    
    add_tag = input('Add a tag for this infrastructure? (Y or N)  ')

    if add_tag == 'Y':
        tag = input('Provide your tag: ')
    elif add_tag == 'N':
        print('Adding a tag assists in identifying similar infrastructure')
    else:
        print('Didnt understand your response. Try again')
        print(add_tag)

    #db_user = os.environ.get("MONGODB_USER")
    #db_pass = os.environ.get("MONGODB_PASS")
    try:
        db_client = pymongo.MongoClient(
            "mongodb+srv://user:pass@iwcluster0.cluster.mongodb.net/?retryWrites=true&w=majority",
            authSource="admin", serverSelectionTimeoutMS=5000, server_api=ServerApi('1')
                )

        database_name = db_client["infra_watch_db"]

        database_collection = database_name["infra_watch"]

        api_result_document = [
            {"ip_address": ipaddr, 
            "domain": domain, 
            "first_seen": first_seen, 
            "provider": reg, 
            "nameserver": nameservr, 
            "country": country, 
            "tag": tag
            },
        ]

        for doc in api_result_document:
            if doc_exists := database_collection.find_one(doc):
                print(f'[!] Document {doc_exists} already exists, skipping.\n')
            else:
                database_collection.insert_many(api_result_document)
                print('[*] Document(s) successfully inserted to MongoDB.')

    except pymongo.errors.OperationFailure as err:
        print(f'[!] {err}')