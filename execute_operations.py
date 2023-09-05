import json
import parse_files
import requests
import prepare_operation_bodies
import boto3
import os

url = f'{parse_files.MIGRATE_TO}/pf-admin-api/v1'
endpoints = {"dataStores": "/dataStores",
             "accessTokenManagers": "/oauth/accessTokenManagers",
             "accessTokenMappings": "/oauth/accessTokenMappings",
             "authPolicies": "/authenticationPolicies/default",
             "authPolicyFragments": "/authenticationPolicies/fragments",
             "authPolicyContracts": "/authenticationPolicyContracts",
             "idpAdapters": "/idp/adapters",
             "passwordCredentialValidators": "/passwordCredentialValidators",
             "spConnections": "/idp/spConnections",
             "clients": "/oauth/clients",
             "keyPairs": "/keyPairs/signing/import",
             "OAuthKeys": "/keyPairs/oauthOpenIdConnect",
             "virtualHosts": "/virtualHostNames",
             "authSessions": "/session/authenticationSessionPolicies",
             "redirectValidation": "/redirectValidation"}

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
secrets = get_secret(os.environ.get('API_SECRET'))
session.auth = (secrets["username"], secrets["pass"])
session.headers.update({'X-XSRF-Header': 'PingFederate'})
session.verify = False

def execute_calls():
    #PUTs and POSTs have the same key values in the same order, so we can iterate this way
    for key, val in prepare_operation_bodies.PUT_Bodies.items():
        #Run POST operations then PUTs
        print(f'\n\n\n\nOperations running now on {key}...\n')
        try:
            for i in range(0, len(prepare_operation_bodies.POST_Bodies[key])):
                json_body = json.loads(json.dumps(prepare_operation_bodies.POST_Bodies[key][i]))
                response = session.post(url=f'{url}{endpoints[key]}', json=json_body)
                print(f'Response code for POST to {url}{endpoints[key]} is {response.status_code} for call'
                      f' made with following JSON:\n {json_body}\n')
                print(f'Response body is as follows:\n {response.content}\n\n\n')
            if key not in ('authPolicies', 'OAuthKeys', 'virtualHosts', 'redirectValidation'):
                for i in range(0, len(prepare_operation_bodies.PUT_Bodies[key])):
                    json_body = json.loads(json.dumps(prepare_operation_bodies.PUT_Bodies[key][i]))
                    response = session.put(url=f'{url}{endpoints[key]}/{prepare_operation_bodies.PUT_IDs[key][i]}',
                                           json=json_body)
                    print(f'Response code for PUT to {url}{endpoints[key]}/{prepare_operation_bodies.PUT_IDs[key][i]} is '
                          f'{response.status_code} with the following JSON:\n {json_body}\n')
                    print(f'Response body is as follows:\n {response.content}\n\n\n')
            else:
                for j in range(0, len(prepare_operation_bodies.PUT_Bodies[key])):
                    json_body = json.loads(json.dumps(prepare_operation_bodies.PUT_Bodies[key][j]))
                    response = session.put(url=f'{url}{endpoints[key]}', json=json_body)
                    print(f'Response code for PUT to {url}{endpoints[key]} is'
                          f' {response.status_code} with the following JSON:\n {json_body}\n')
                    print(f'Response body is as follows:\n {response.content}\n\n\n')
        except requests.exceptions.RequestException as e:
            print('Unexpected result code for: ', e)

execute_calls()

print('\n\n\n\nOperations Completed.  Migration Complete!\n\n\n\n')
