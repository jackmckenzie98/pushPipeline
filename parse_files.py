# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import json
import requests
import boto3
import os

migrate_to = os.environ.get('migrate_to')
migrate_from = os.environ.get('migrate_from')
file_path = os.getcwd()
final_path = os.path.join(file_path, r'artifactsPull')
cert_path = os.path.join(final_path, r'certs')
#prepare a certs folder to import them in the push
if not os.path.exists(cert_path):
    os.makedirs(os.path.join(final_path, f'certs'))

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

def call_existing_environment():
    session = requests.Session()
    secrets = get_secret('debian-pf-api-secret')
    session.auth =(secrets["username"], secrets["pass"])
    session.headers.update({'X-XSRF-Header': 'PingFederate'})
    session.verify = False
    existing_clients = session.get(f'{migrate_to}/pf-admin-api/v1/oauth/clients').json()
    existing_authPols = session.get(f'{migrate_to}/pf-admin-api/v1/authenticationPolicies/default').json()
    existing_idpAdapters = session.get(f'{migrate_to}/pf-admin-api/v1/idp/adapters').json()
    existing_spConns = session.get(f'{migrate_to}/pf-admin-api/v1/idp/spConnections').json()
    existing_PCVs = session.get(f'{migrate_to}/pf-admin-api/v1/passwordCredentialValidators').json()
    existing_accessTokenManagers = session.get(f'{migrate_to}/pf-admin-api/v1/oauth/accessTokenManagers').json()
    existing_accessTokenMappings = session.get(f'{migrate_to}/pf-admin-api/v1/oauth/accessTokenMappings').json()
    existing_authPolicyContracts = session.get(f'{migrate_to}/pf-admin-api/v1/authenticationPolicyContracts').json()
    existing_dataStores = session.get(f'{migrate_to}/pf-admin-api/v1/dataStores').json()
    existing_keyPairs = session.get(f'{migrate_to}/pf-admin-api/v1/keyPairs/signing').json()
    return existing_clients, existing_authPols, existing_idpAdapters, existing_spConns, existing_PCVs, \
        existing_accessTokenManagers, existing_accessTokenMappings, existing_authPolicyContracts, \
        existing_dataStores, existing_keyPairs

def ingest_artifacts():
    clientsArt = json.load(open('./artifactsPull/clients.json'))
    authPoliciesArt = json.load(open('./artifactsPull/authPolicies.json'))
    idpAdaptersArt = json.load(open('./artifactsPull/idpAdapters.json'))
    spConnectionsArt = json.load(open('./artifactsPull/spConnections.json'))
    passwordCredentialValidatorsArt = json.load(open('./artifactsPull/passwordCredentialValidators.json'))
    accessTokenManagersArt = json.load(open('./artifactsPull/accessTokenManagers.json'))
    accessTokenMappingsArt = json.load(open('./artifactsPull/accessTokenMappings.json'))
    authPolicyContractsArt = json.load(open('./artifactsPull/authPolicyContracts.json'))
    dataStoresArt = json.load(open('./artifactsPull/dataStores.json'))
    keyPairsArt = json.load(open('./artifactsPull/keyPairs.json'))
    return clientsArt, authPoliciesArt, idpAdaptersArt, spConnectionsArt, passwordCredentialValidatorsArt, \
        accessTokenManagersArt, accessTokenMappingsArt, authPolicyContractsArt, dataStoresArt, keyPairsArt

def intake_env_files():
    clientsEnv = json.load(open('Env files/clients.json'))
    authPolEnv = json.load(open('Env files/authPolicies.json'))
    idpAdaptersEnv = json.load(open('Env files/idpAdapters.json'))
    spConnEnv = json.load(open('Env files/spConnections.json'))
    PCVEnv = json.load(open('Env files/passwordCredentialValidators.json'))
    accessTokenManagersEnv = json.load(open('Env files/accessTokenManagers.json'))
    accessTokenMappingsEnv = json.load(open('Env files/accessTokenMappings.json'))
    authPolicyContractsEnv = json.load(open('Env files/authPolicyContracts.json'))
    dataStoresEnv = json.load(open('Env files/dataStores.json'))
    return clientsEnv, authPolEnv, idpAdaptersEnv, spConnEnv, PCVEnv, accessTokenManagersEnv,\
        accessTokenMappingsEnv, authPolicyContractsEnv, dataStoresEnv

def pull_certs():
    migrate_from = os.environ.get('migrate_from')
    session = requests.Session()
    secrets = get_secret('debian-pf-api-secret')
    encryption_pass = get_secret('encryption-cert-pass')["encryptionPass"]
    session.auth = (secrets["username"], secrets["pass"])
    session.headers.update({'X-XSRF-Header': 'PingFederate'})
    session.verify = False
    cert_ids = []
    loaded = json.load(open('artifactsPull/keyPairs.json'))
    for k,v in loaded.items():
        for val in v:
            cert_ids.append(val['id'])
    for id in cert_ids:
        json_body = {"password": f"{encryption_pass}"}
        response = session.post(f'{migrate_from}/pf-admin-api/v1/keyPairs/signing/{id}/pem', json=json_body)
        f = open(f"{final_path}\\certs\\{id}.pem", 'w+')
        f.write(response.text)
        f.close()


clientsArt, authPolsArt, idpAdaptersArt, spConnsArt, passwordCredentialValidatorsArt, accessTokenManagersArt, \
    accessTokenMappingsArt, authPolicyContractsArt, dataStoresArt, keyPairsArt = ingest_artifacts()

clientsEnv, authPolsEnv, idpAdaptersEnv, spConnEnv, PCVEnv, accessTokenManagersEnv, accessTokenMappingsEnv, \
    authPolicyContractsEnv, dataStoresEnv = intake_env_files()

existingClients, existingAuthPols, existingIDPAdapters, existingSPConns, existingPCVs, existingAccessTokenManagers,\
    existingAccessTokenMappings, existing_authPolicyContracts, existingDataStores, existingKeyPairs\
    = call_existing_environment()

pull_certs()
print('File parsing has been completed.')
