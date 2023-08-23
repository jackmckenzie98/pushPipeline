import json
import parse_files
import requests
import prep_post_bodies
import boto3

url = f'{parse_files.migrate_to}/pf-admin-api/v1'


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


session = requests.Session()
secrets = get_secret('debian-pf-api-secret')
session.auth = (secrets["username"], secrets["pass"])
session.headers.update({'X-XSRF-Header': 'PingFederate'})
session.verify = False


def execute_idp_adapters():
    for i in range(0, len(prep_post_bodies.POST_Bodies["idpAdapters"])):
        print('Running POST Calls on IDP adapters...\n\n')
        json_body = json.loads(json.dumps(prep_post_bodies.POST_Bodies["idpAdapters"][i]))
        response = \
            session.post(url=f'{url}/idp/adapters', json=json_body)
        print(f'Response Code for POST is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
        print(f'Here is the content of the response:\n {response.content}\n\n')
    if len(prep_post_bodies.PUT_IDs["idpAdapters"]) > 0:
        for j in range(0, len(prep_post_bodies.PUT_IDs["idpAdapters"])):
            print('Running PUT Calls on IDP Adapters(update)...\n\n')
            json_body = json.loads(json.dumps(prep_post_bodies.PUT_Bodies["idpAdapters"][j]))
            response = \
                session.put(url=f'{url}/idp/adapters/{prep_post_bodies.PUT_IDs["idpAdapters"][j]}', json=json_body)
            print(f'Response Code for PUT to {url}/idp/adapters/{prep_post_bodies.PUT_IDs["idpAdapters"][j]}'
                  f' is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
            print(f'Here is the content of the response:\n {response.content}\n\n')


def execute_access_token_managers():
    for i in range(0, len(prep_post_bodies.POST_Bodies["accessTokenManagers"])):
        print('Running POST Calls on Access Token Managers...\n\n')
        json_body = json.loads(json.dumps(prep_post_bodies.POST_Bodies["accessTokenManagers"][i]))
        response = \
            session.post(url=f'{url}/oauth/accessTokenManagers', json=json_body)
        print(f'Response Code for POST is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
        print(f'Here is the content of the response:\n {response.content}\n\n')
    if len(prep_post_bodies.PUT_IDs["accessTokenManagers"]) > 0:
        for j in range(0, len(prep_post_bodies.PUT_IDs["accessTokenManagers"])):
            print('Running PUT Calls on Access Token Managers(update)...\n\n')
            json_body = json.loads(json.dumps(prep_post_bodies.PUT_Bodies["accessTokenManagers"][j]))
            response = \
                session.put(url=f'{url}/oauth/accessTokenManagers/{prep_post_bodies.PUT_IDs["accessTokenManagers"][j]}',
                            json=json_body)
            print(
                f'Response Code for PUT to {url}/oauth/accessTokenManagers/{prep_post_bodies.PUT_IDs["accessTokenManagers"][j]}'
                f' is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
            print(f'Here is the content of the response:\n {response.content}\n\n')


def execute_access_token_mappings():
    for i in range(0, len(prep_post_bodies.POST_Bodies["accessTokenMappings"])):
        print('Running POST Calls on Access Token Mappings...\n\n')
        json_body = json.loads(json.dumps(prep_post_bodies.POST_Bodies["accessTokenMappings"][i]))
        response = \
            session.post(url=f'{url}/oauth/accessTokenMappings', json=json_body)
        print(f'Response Code for POST is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
        print(f'Here is the content of the response:\n {response.content}\n\n')
    if len(prep_post_bodies.PUT_IDs["accessTokenMappings"]) > 0:
        for j in range(0, len(prep_post_bodies.PUT_IDs["accessTokenMappings"])):
            print('Running PUT Calls on Access Token Mappings(update)...\n\n')
            json_body = json.loads(json.dumps(prep_post_bodies.PUT_Bodies["accessTokenMappings"][j]))
            response = \
                session.put(url=f'{url}/oauth/accessTokenMappings/{prep_post_bodies.PUT_IDs["accessTokenMappings"][j]}',
                            json=json_body)
            print(
                f'Response Code for PUT to {url}/oauth/accessTokenMappings/{prep_post_bodies.PUT_IDs["accessTokenMappings"][j]}'
                f' is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
            print(f'Here is the content of the response:\n {response.content}\n\n')


# Issue with data stores logic somewhere in POST, same for access token managers.  Need to replace encryptedValue with
# value as the key, and the value of the encryptedValue JSON field with the actual password value to inject properly
# programmatically.
def execute_data_stores():
    for i in range(0, len(prep_post_bodies.POST_Bodies["dataStores"])):
        print('Running POST Calls on Data Stores...\n\n')
        json_body = json.loads(json.dumps(prep_post_bodies.POST_Bodies["dataStores"][i]))
        response = \
            session.post(url=f'{url}/dataStores', json=json_body)
        print(f'Response Code for POST is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
        print(f'Here is the content of the response:\n {response.content}\n\n')
    if len(prep_post_bodies.PUT_IDs["dataStores"]) > 0:
        for j in range(0, len(prep_post_bodies.PUT_IDs["dataStores"])):
            print('Running PUT Calls on Data Stores(update)...\n\n')
            json_body = json.loads(json.dumps(prep_post_bodies.PUT_Bodies["dataStores"][j]))
            response = \
                session.put(url=f'{url}/dataStores/{prep_post_bodies.PUT_IDs["dataStores"][j]}', json=json_body)
            print(f'Response Code for PUT to {url}/dataStores/{prep_post_bodies.PUT_IDs["dataStores"][j]}'
                  f' is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
            print(f'Here is the content of the response:\n {response.content}\n\n')


def execute_clients():
    for i in range(0, len(prep_post_bodies.POST_Bodies["clients"])):
        print('Running POST Calls on OAuth Clients...\n\n')
        json_body = json.loads(json.dumps(prep_post_bodies.POST_Bodies["clients"][i]))
        response = \
            session.post(url=f'{url}/oauth/clients', json=json_body)
        print(f'Response Code for POST is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
        print(f'Here is the content of the response:\n {response.content}\n\n')
    if len(prep_post_bodies.PUT_IDs["clients"]) > 0:
        for j in range(0, len(prep_post_bodies.PUT_IDs["clients"])):
            print('Running PUT Calls on Access Token Mappings(update)...\n\n')
            json_body = json.loads(json.dumps(prep_post_bodies.PUT_Bodies["clients"][j]))
            response = \
                session.put(url=f'{url}/oauth/clients/{prep_post_bodies.PUT_IDs["clients"][j]}',
                            json=json_body)
            print(
                f'Response Code for PUT to {url}/oauth/clients/{prep_post_bodies.PUT_IDs["clients"][j]}'
                f' is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
            print(f'Here is the content of the response:\n {response.content}\n\n')


def execute_password_credential_validators():
    for i in range(0, len(prep_post_bodies.POST_Bodies["passwordCredentialValidators"])):
        print('Running POST Calls on PCVs...\n\n')
        json_body = json.loads(json.dumps(prep_post_bodies.POST_Bodies["passwordCredentialValidators"][i]))
        response = \
            session.post(url=f'{url}/passwordCredentialValidators', json=json_body)
        print(f'Response Code for POST is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
        print(f'Here is the content of the response:\n {response.content}\n\n')
    if len(prep_post_bodies.PUT_IDs["passwordCredentialValidators"]) > 0:
        for j in range(0, len(prep_post_bodies.PUT_IDs["passwordCredentialValidators"])):
            print('Running PUT Calls on Password Credential Validators(update)...\n\n')
            json_body = json.loads(json.dumps(prep_post_bodies.PUT_Bodies["passwordCredentialValidators"][j]))
            response = \
                session.put(
                    url=f'{url}/passwordCredentialValidators/{prep_post_bodies.PUT_IDs["passwordCredentialValidators"][j]}',
                    json=json_body)
            print(
                f'Response Code for PUT to {url}/passwordCredentialValidators/{prep_post_bodies.PUT_IDs["passwordCredentialValidators"][j]}'
                f' is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
            print(f'Here is the content of the response:\n {response.content}\n\n')

def execute_authentication_policy_contracts():
    for i in range(0, len(prep_post_bodies.POST_Bodies["authPolicyContracts"])):
        print('Running POST Calls on Auth Policy Contracts...\n\n')
        json_body = json.loads(json.dumps(prep_post_bodies.POST_Bodies["authPolicyContracts"][i]))
        response = \
            session.post(url=f'{url}/authenticationPolicyContracts', json=json_body)
        print(f'Response Code for POST is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
        print(f'Here is the content of the response:\n {response.content}\n\n')
    if len(prep_post_bodies.PUT_IDs["authPolicyContracts"]) > 0:
        for j in range(0, len(prep_post_bodies.PUT_IDs["authPolicyContracts"])):
            print('Running PUT Calls on Auth Policy Contracts (update)...\n\n')
            json_body = json.loads(json.dumps(prep_post_bodies.PUT_Bodies["authPolicyContracts"][j]))
            response = \
                session.put(url=f'{url}/authenticationPolicyContracts/{prep_post_bodies.PUT_IDs["authPolicyContracts"][j]}', json=json_body)
            print(f'Response Code for PUT to {url}/authenticationPolicyContracts/{prep_post_bodies.PUT_IDs["authPolicyContracts"][j]}'
                  f' is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
            print(f'Here is the content of the response:\n {response.content}\n\n')

def execute_sp_connections():
    for i in range(0, len(prep_post_bodies.POST_Bodies["spConnections"])):
        print('Running POST Calls on SP Connections...\n\n')
        json_body = json.loads(json.dumps(prep_post_bodies.POST_Bodies["spConnections"][i]))
        response = \
            session.post(url=f'{url}/idp/spConnections', json=json_body)
        print(f'Response Code for POST is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
        print(f'Here is the content of the response:\n {response.content}\n\n')
    if len(prep_post_bodies.PUT_IDs["spConnections"]) > 0:
        for j in range(0, len(prep_post_bodies.PUT_IDs["spConnections"])):
            print('Running PUT Calls on SP Connections(update)...\n\n')
            json_body = json.loads(json.dumps(prep_post_bodies.PUT_Bodies["spConnections"][j]))
            response = \
                session.put(url=f'{url}/idp/spConnections/{prep_post_bodies.PUT_IDs["spConnections"][j]}',
                            json=json_body)
            print(
                f'Response Code for PUT to {url}/idp/spConnections/{prep_post_bodies.PUT_IDs["spConnections"][j]}'
                f' is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
            print(f'Here is the content of the response:\n {response.content}\n\n')

def execute_authentication_policy():
    #for i in range(0, len(prep_post_bodies.POST_Bodies["authPolicies"])):
    #    print("Running POST Calls on Auth Policies")
    #    json_body = json.loads(json.dumps(prep_post_bodies.POST_Bodies["authPolicies"][i]))
    #    response = \
    #        session.post(url=f'{url}/authenticationPolicies/default', json=json_body)
    #    print(f'Response Code for POST is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
    #    print(f'Here is the content of the response:\n {response.content}\n\n')
    if len(prep_post_bodies.POST_Bodies["authPolicies"]) > 0:
        for j in range(0, len(prep_post_bodies.POST_Bodies["authPolicies"])):
            print('Running PUT Calls on Auth Policies(update)...\n\n')
            json_body = json.loads(json.dumps(prep_post_bodies.POST_Bodies["authPolicies"][j]))
            response = \
                session.put(url=f'{url}/authenticationPolicies/default',
                            json=json_body)
            print(
                f'Response Code for PUT to {url}/authenticationPolicies/default'
                f' is {response.status_code} for call made with following JSON:\n {json_body}\n\n')
            print(f'Here is the content of the response:\n {json.dumps(json_body, indent=2)}\n\n')

def execute_keypair_signing():
    if len(prep_post_bodies.POST_Bodies["keyPairs"]) > 0:
        for i in range(0, len(prep_post_bodies.POST_Bodies["keyPairs"])):
            print("Importing Key Pair Certs...\n\n")
            json_body = json.loads(json.dumps(prep_post_bodies.POST_Bodies["keyPairs"][i]))
            response = session.post(url=f'{url}/keyPairs/signing/import',
                                    json=json_body)
            print(
                f'Response Code for POST of Key Pair with ID {prep_post_bodies.POST_Bodies["keyPairs"][i]["id"]}'
                f'is {response.status_code}'
            )
            print(f'Here is the response\'s content: \n {response.content}\n\n')


execute_keypair_signing()
execute_idp_adapters()
execute_access_token_managers()
execute_access_token_mappings()
execute_data_stores()
execute_clients()
execute_password_credential_validators()
execute_authentication_policy_contracts()
execute_sp_connections()
execute_authentication_policy()


