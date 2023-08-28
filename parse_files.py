# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import json
import requests
import boto3
import os

MIGRATE_TO = os.environ.get('MIGRATE_TO')
MIGRATE_FROM = os.environ.get('MIGRATE_FROM')
WORKING_PATH = os.path.dirname(__file__)
ARTIFACTS_PATH = os.path.join(WORKING_PATH, r'artifactsToPush')
ENV_FILES = os.path.join(WORKING_PATH, r'Env files')
CERT_FILES = os.path.join(ARTIFACTS_PATH, r'certs')
#Prepare a certs folder to import them in the push
if not os.path.exists(CERT_FILES):
    os.makedirs(os.path.join(ARTIFACTS_PATH, f'certs'))


def get_secret(secret_name):
    region_name = "us-east-1"
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    secret_response = client.get_secret_value(
        SecretId=secret_name
    )
    secrets = json.loads(secret_response['SecretString'])
    return secrets


# Format all of the existing objects in MIGRATE_TO environment to match what the artifacts look like for 
# comparison's sake
def format_object(list_deal):
    for i in range(0, len(list_deal)):
        #Check if the type is a list, because if so it should be wrapped in "items" key
        if type(list_deal[i]) is list:
            list_deal[i] = {
                "items" : list_deal[i]
            }
        #Check if type is a dictionary but does not have "items" key that matches other file formats
        if type(list_deal[i]) is dict:
            if 'items' not in list_deal[i]:
                list_deal[i] = {
                    "items": [list_deal[i]]
                }
    return list_deal

def call_existing_environment():
    session = requests.Session()
    secrets = get_secret(os.environ.get("API_SECRET"))
    session.auth =(secrets["username"], secrets["pass"])
    session.headers.update({'X-XSRF-Header': 'PingFederate'})
    session.verify = False
    existing_clients = session.get(f'{MIGRATE_TO}/pf-admin-api/v1/oauth/clients').json()
    existing_authPols = session.get(f'{MIGRATE_TO}/pf-admin-api/v1/authenticationPolicies/default').json()
    existing_authPolFragments = session.get(f'{MIGRATE_TO}/pf-admin-api/v1/authenticationPolicies/fragments').json()
    existing_idpAdapters = session.get(f'{MIGRATE_TO}/pf-admin-api/v1/idp/adapters').json()
    existing_spConns = session.get(f'{MIGRATE_TO}/pf-admin-api/v1/idp/spConnections').json()
    existing_PCVs = session.get(f'{MIGRATE_TO}/pf-admin-api/v1/passwordCredentialValidators').json()
    existing_accessTokenManagers = session.get(f'{MIGRATE_TO}/pf-admin-api/v1/oauth/accessTokenManagers').json()
    existing_accessTokenMappings = session.get(f'{MIGRATE_TO}/pf-admin-api/v1/oauth/accessTokenMappings').json()
    existing_authPolicyContracts = session.get(f'{MIGRATE_TO}/pf-admin-api/v1/authenticationPolicyContracts').json()
    existing_dataStores = session.get(f'{MIGRATE_TO}/pf-admin-api/v1/dataStores').json()
    existing_keyPairs = session.get(f'{MIGRATE_TO}/pf-admin-api/v1/keyPairs/signing').json()
    return [existing_clients, existing_authPols, existing_authPolFragments, existing_idpAdapters, existing_spConns, existing_PCVs, \
        existing_accessTokenManagers, existing_accessTokenMappings, existing_authPolicyContracts, \
        existing_dataStores, existing_keyPairs]

def ingest_artifacts():
    clientsArt = json.load(open(os.path.join(ARTIFACTS_PATH, r'clients.json')))
    authPoliciesArt = json.load(open(os.path.join(ARTIFACTS_PATH, r'authPolicies.json')))
    authPolFragmentsArt = json.load(open(os.path.join(ARTIFACTS_PATH, r'authenticationPolicyFragments.json')))
    idpAdaptersArt = json.load(open(os.path.join(ARTIFACTS_PATH, r'idpAdapters.json')))
    spConnectionsArt = json.load(open(os.path.join(ARTIFACTS_PATH, r'spConnections.json')))
    passwordCredentialValidatorsArt = json.load(open(os.path.join(ARTIFACTS_PATH, r'passwordCredentialValidators.json')))
    accessTokenManagersArt = json.load(open(os.path.join(ARTIFACTS_PATH, r'accessTokenManagers.json')))
    accessTokenMappingsArt = json.load(open(os.path.join(ARTIFACTS_PATH, r'accessTokenMappings.json')))
    authPolicyContractsArt = json.load(open(os.path.join(ARTIFACTS_PATH, r'authPolicyContracts.json')))
    dataStoresArt = json.load(open(os.path.join(ARTIFACTS_PATH, r'dataStores.json')))
    keyPairsArt = json.load(open(os.path.join(ARTIFACTS_PATH, r'keyPairs.json')))
    return clientsArt, authPoliciesArt, authPolFragmentsArt, idpAdaptersArt, spConnectionsArt, passwordCredentialValidatorsArt, \
        accessTokenManagersArt, accessTokenMappingsArt, authPolicyContractsArt, dataStoresArt, keyPairsArt

def intake_env_files():
    clientsEnv = json.load(open(os.path.join(ENV_FILES, r'clients.json')))
    authPolEnv = json.load(open(os.path.join(ENV_FILES, r'authPolicies.json')))
    authPolFragmentsEnv = json.load(open(os.path.join(ENV_FILES, r'authenticationPolicyFragments.json')))
    idpAdaptersEnv = json.load(open(os.path.join(ENV_FILES, r'idpAdapters.json')))
    spConnEnv = json.load(open(os.path.join(ENV_FILES, r'spConnections.json')))
    PCVEnv = json.load(open(os.path.join(ENV_FILES, r'passwordCredentialValidators.json')))
    accessTokenManagersEnv = json.load(open(os.path.join(ENV_FILES, r'accessTokenManagers.json')))
    accessTokenMappingsEnv = json.load(open(os.path.join(ENV_FILES, r'accessTokenMappings.json')))
    authPolicyContractsEnv = json.load(open(os.path.join(ENV_FILES, r'authPolicyContracts.json')))
    dataStoresEnv = json.load(open(os.path.join(ENV_FILES, r'dataStores.json')))
    return clientsEnv, authPolEnv, authPolFragmentsEnv, idpAdaptersEnv, spConnEnv, PCVEnv, accessTokenManagersEnv,\
        accessTokenMappingsEnv, authPolicyContractsEnv, dataStoresEnv

def pull_certs():
    session = requests.Session()
    secrets = get_secret(os.environ.get('API_SECRET'))
    encryption_pass = get_secret(os.environ.get("ENCRYPTION_PASS_NAME"))["encryptionPass"]
    session.auth = (secrets["username"], secrets["pass"])
    session.headers.update({'X-XSRF-Header': 'PingFederate'})
    session.verify = False
    cert_ids = []
    loaded = json.load(open(f'{ARTIFACTS_PATH}/keyPairs.json'))
    for k,v in loaded.items():
        for val in v:
            cert_ids.append(val['id'])
    for id in cert_ids:
        json_body = {"password": f"{encryption_pass}"}
        response = session.post(f'{MIGRATE_FROM}/pf-admin-api/v1/keyPairs/signing/{id}/pem', json=json_body)
        f = open(f"{CERT_FILES}/{id}.pem", 'w+')
        f.write(response.text)
        f.close()


clientsArt, authPolsArt, authPolFragmentsArt, idpAdaptersArt, spConnsArt, passwordCredentialValidatorsArt, accessTokenManagersArt, \
    accessTokenMappingsArt, authPolicyContractsArt, dataStoresArt, keyPairsArt = ingest_artifacts()

clientsEnv, authPolsEnv, authPolFragmentsEnv, idpAdaptersEnv, spConnEnv, PCVEnv, accessTokenManagersEnv, accessTokenMappingsEnv, \
    authPolicyContractsEnv, dataStoresEnv = intake_env_files()

existingClients, existingAuthPols, existingAuthPolFragments, existingIDPAdapters, existingSPConns, existingPCVs, existingAccessTokenManagers,\
    existingAccessTokenMappings, existing_authPolicyContracts, existingDataStores, existingKeyPairs\
    = format_object(call_existing_environment())


if __name__ == '__main__':
    pull_certs()
    print('File parsing script has been completed')
    print(f'\n\n{existingAccessTokenMappings}')