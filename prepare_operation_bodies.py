import json
import parse_files
import os

PUT_IDs = {"dataStores": [],
           "accessTokenManagers": [],
           "accessTokenMappings": [],
           "authPolicies": [],
           "authPolicyFragments": [],
           "authPolicyContracts": [],
           "idpAdapters": [],
           "passwordCredentialValidators": [],
           "spConnections": [],
           "clients": [],
           "keyPairs": []
           }
PUT_Bodies = {"dataStores": [],
              "accessTokenManagers": [],
              "accessTokenMappings": [],
              "authPolicies": [],
              "authPolicyFragments": [],
              "authPolicyContracts": [],
              "idpAdapters": [],
              "passwordCredentialValidators": [],
              "spConnections": [],
              "clients": [],
              "keyPairs": []
              }
POST_Bodies = {"dataStores": [],
               "accessTokenManagers": [],
               "accessTokenMappings": [],
               "authPolicies": [],
               "authPolicyFragments": [],
               "authPolicyContracts": [],
               "idpAdapters": [],
               "passwordCredentialValidators": [],
               "spConnections": [],
               "clients": [],
               "keyPairs": []
               }


def prepare_SP_operations():
    env_inject = parse_files.spConnEnv['example']['location']
    existing_ids = []
    for i in range(0, len(parse_files.existingSPConns['items'])):
        existing_ids.append(parse_files.existingSPConns['items'][i]['entityId'])

    if len(parse_files.existingSPConns) > 0:
        for item in parse_files.spConnsArt.values():
            for list_item in item:
                list_item = replace_location_recursive(list_item, f"{parse_files.migrate_from}", env_inject)
                # If the artifact is not in the existing configuration, we will add it to the creation list(objects to be created)
                if list_item['entityId'] not in existing_ids:
                    POST_Bodies["spConnections"].append(list_item)
                # Otherwise, means it exists in the configuration already, and we will store the ID for a PUT operation
                else:
                    PUT_IDs["spConnections"].append(list_item["id"])
                    PUT_Bodies["spConnections"].append(list_item)
    else:
        POST_Bodies["spConnections"] = replace_location_recursive(parse_files.spConnsArt['items'],
                                                                  f"{parse_files.migrate_from}",
                                                                  env_inject)


def prepare_PCV_operations():
    env_inject = parse_files.PCVEnv['example']['location']
    existing_ids = []
    for i in range(0, len(parse_files.existingPCVs['items'])):
        existing_ids.append(parse_files.existingPCVs['items'][i]['id'])

    if len(parse_files.existingPCVs) > 0:
        for item in parse_files.passwordCredentialValidatorsArt.values():
            for list_item in item:
                list_item = replace_location_recursive(list_item, parse_files.migrate_from, env_inject)
                if list_item['id'] not in existing_ids:
                    POST_Bodies["passwordCredentialValidators"].append(list_item)
                else:
                    PUT_IDs["passwordCredentialValidators"].append(list_item["id"])
                    PUT_Bodies["passwordCredentialValidators"].append(list_item)
    else:
        POST_Bodies["passwordCredentialValidators"] = replace_location_recursive(
            parse_files.passwordCredentialValidatorsArt['items'], f"{parse_files.migrate_from}", env_inject)

    for k in range(0, len(POST_Bodies["passwordCredentialValidators"])):
        if POST_Bodies["passwordCredentialValidators"][k]['id'] != "ProvisionerDS":
            POST_Bodies["passwordCredentialValidators"][k] = inject_secret_values(
                POST_Bodies["passwordCredentialValidators"][k], "encryptedValue",
                "value",
                parse_files.get_secret('PCVPass')
                ["PCVPass"])

    for l in range(0, len(PUT_Bodies["passwordCredentialValidators"])):
        PUT_Bodies["passwordCredentialValidators"][l] = inject_secret_values(
            PUT_Bodies["passwordCredentialValidators"][l], "encryptedValue", "value",
            parse_files.get_secret('PCVPass')
            ["PCVPass"])


# this needs fixed to check for existence properly
def prepare_client_operations():
    existing_ids = []
    env_inject = parse_files.clientsEnv['example']['location']
    # Get a list of client IDs that exist to determine whether it will be PUT or POST
    for i in range(0, len(parse_files.existingClients['items'])):
        existing_ids.append(parse_files.existingClients['items'][i]['clientId'])

    if len(parse_files.existingClients['items']) > 0:
        for i in range(0, len(parse_files.clientsArt['items'])):
            new_body = replace_location_recursive(parse_files.clientsArt['items'][i], f"{parse_files.migrate_from}",
                                                  env_inject)
            if new_body['clientId'] not in existing_ids:
                POST_Bodies["clients"].append(new_body)
            else:
                PUT_IDs["clients"].append(new_body["clientId"])
                PUT_Bodies["clients"].append(new_body)
    else:
        POST_Bodies["clients"] = replace_location_recursive(parse_files.clientsArt['items'], "https://debian-"
                                                                                             "pingfed:9999", env_inject)


def prepare_accessTokenManager_operations():
    env_inject = parse_files.accessTokenManagersEnv['example']['location']
    # Get the existing IDs to see if it already exists and thus will take a PUT instead of POST
    existing_ids = []
    for i in range(0, len(parse_files.existingAccessTokenManagers['items'])):
        existing_ids.append(parse_files.existingAccessTokenManagers['items'][i]['id'])

    if len(parse_files.existingAccessTokenManagers['items']) > 0:
        for item in parse_files.accessTokenManagersArt.values():
            for list_item in item:
                list_item = replace_location_recursive(list_item, f"{parse_files.migrate_from}", env_inject)
                if list_item['id'] not in existing_ids:
                    POST_Bodies["accessTokenManagers"].append(list_item)
                else:
                    PUT_IDs["accessTokenManagers"].append(list_item["id"])
                    PUT_Bodies["accessTokenManagers"].append(list_item)
    else:
        POST_Bodies["accessTokenManagers"] = replace_location_recursive(parse_files.accessTokenManagersArt['items'],
                                                                        f"{parse_files.migrate_from}", env_inject)


def prepare_accessTokenMappings_operations():
    env_inject = parse_files.accessTokenMappingsEnv['example']['location']
    if len(parse_files.existingAccessTokenMappings) > 0:
        for item in parse_files.accessTokenMappingsArt:
            item = replace_location_recursive(item, f"{parse_files.migrate_from}", env_inject)
            if item not in parse_files.existingAccessTokenMappings:
                POST_Bodies["accessTokenMappings"].append(item)
            else:
                PUT_IDs["accessTokenMappings"].append(item["id"])
                PUT_Bodies["accessTokenMappings"].append(item)
    else:
        POST_Bodies["accessTokenMappings"] = replace_location_recursive(parse_files.accessTokenMappingsArt,
                                                                        f"{parse_files.migrate_from}",
                                                                        env_inject)


def prepare_dataStore_operations():
    env_inject = parse_files.dataStoresEnv['example']['location']
    existing_ids = []
    for i in range(0, len(parse_files.existingDataStores['items'])):
        existing_ids.append(parse_files.existingDataStores['items'][i]['id'])
    if len(existing_ids) > 0:
        for j in range(0, len(parse_files.dataStoresArt['items'])):
            if parse_files.dataStoresArt['items'][j]['id'] not in existing_ids:
                new_body = replace_location_recursive(parse_files.dataStoresArt["items"][j],
                                                      f"{parse_files.migrate_from}",
                                                      env_inject
                                                      )
                POST_Bodies["dataStores"].append(new_body)
            # Ignore default DB, don't touch it
            elif parse_files.dataStoresArt['items'][j]['id'] != "ProvisionerDS":
                new_body = replace_location_recursive(parse_files.dataStoresArt['items'][j],
                                                      f"{parse_files.migrate_from}",
                                                      env_inject
                                                      )
                PUT_Bodies["dataStores"].append(new_body)
                PUT_IDs["dataStores"].append(new_body['id'])
    else:
        POST_Bodies["dataStores"] = replace_location_recursive(parse_files.dataStoresArt, "https://debian-pingfed:"
                                                                                          "9999", env_inject)
    # Inject secrets into the POST/PUT bodies
    for k in range(0, len(POST_Bodies["dataStores"])):
        if POST_Bodies["dataStores"][k]['id'] != "ProvisionerDS":
            POST_Bodies["dataStores"][k] = inject_secret_values(POST_Bodies["dataStores"][k], "encryptedPassword",
                                                                "password",
                                                                parse_files.get_secret('PCVPass')
                                                                ["PCVPass"])
    for l in range(0, len(PUT_Bodies["dataStores"])):
        PUT_Bodies["dataStores"][l] = inject_secret_values(PUT_Bodies["dataStores"][l], "encryptedPassword", "password",
                                                           parse_files.get_secret('PCVPass')
                                                           ["PCVPass"])


def prepare_idpAdapter_operations():
    env_inject = parse_files.idpAdaptersEnv['example']['location']
    existing_ids = []
    for i in range(0, len(parse_files.existingIDPAdapters['items'])):
        existing_ids.append(parse_files.existingIDPAdapters['items'][i]['id'])
    if len(parse_files.existingIDPAdapters) > 0:
        for item in parse_files.idpAdaptersArt['items']:
            item = replace_location_recursive(item, f"{parse_files.migrate_from}", env_inject)
            if item['id'] not in existing_ids:
                POST_Bodies["idpAdapters"].append(item)
            else:
                PUT_IDs["idpAdapters"].append(item["id"])
                PUT_Bodies["idpAdapters"].append(item)
    else:
        POST_Bodies["idpAdapters"] = replace_location_recursive(parse_files.idpAdaptersArt['items'],
                                                                f"{parse_files.migrate_from}",
                                                                env_inject
                                                                )
    for k in range(0, len(POST_Bodies["idpAdapters"])):
        if POST_Bodies["idpAdapters"][k]['id'] != "ProvisionerDS":
            POST_Bodies["idpAdapters"][k] = inject_secret_values(POST_Bodies["idpAdapters"][k], "encryptedValue",
                                                                 "value",
                                                                 parse_files.get_secret('intune-adapter-secret')
                                                                 ["intune-adapter-secret"])
    for l in range(0, len(PUT_Bodies["idpAdapters"])):
        PUT_Bodies["idpAdapters"][l] = inject_secret_values(PUT_Bodies["idpAdapters"][l], "encryptedValue", "value",
                                                            parse_files.get_secret('intune-adapter-secret')
                                                            ["intune-adapter-secret"])


def prepare_authPolicyContract_operations():
    env_inject = parse_files.authPolicyContractsEnv['example']['location']
    existing_ids = []
    for i in range(0, len(parse_files.existing_authPolicyContracts['items'])):
        existing_ids.append(parse_files.existing_authPolicyContracts['items'][i]['id'])
    if len(parse_files.existing_authPolicyContracts) > 0:
        for item in parse_files.authPolicyContractsArt['items']:
            item = replace_location_recursive(item, f"{parse_files.migrate_from}", env_inject)
            if item['id'] not in existing_ids:
                POST_Bodies["authPolicyContracts"].append(item)
            else:
                PUT_IDs["authPolicyContracts"].append(item["id"])
                PUT_Bodies["authPolicyContracts"].append(item)
    else:
        POST_Bodies["authPolicyContracts"] = replace_location_recursive(parse_files.authPolicyContractsArt['items'],
                                                                        f"{parse_files.migrate_from}",
                                                                        env_inject
                                                                        )


# This probably needs evaluation as the POST/PUTs for authn policies are a bit weird.
def prepare_authPolicy_operations():
    env_inject = parse_files.authPolsEnv['example']['location']
    existing_ids = []
    for i in range(0, len(parse_files.existingAuthPols['authnSelectionTrees'])):
        existing_ids.append(parse_files.existingAuthPols['authnSelectionTrees'][i]['rootNode']["action"]
                            ["authenticationSource"]["sourceRef"]["id"])
    POST_Bodies["authPolicies"].append(replace_location_recursive(parse_files.authPolsArt,
                                                                  f"{parse_files.migrate_from}",
                                                                  env_inject))


def prepare_authPolicyFragments_operations():
    env_inject = parse_files.authPolFragmentsEnv['example']['location']
    if len(parse_files.existingAuthPolFragments) > 0:
        for item in parse_files.authPolFragmentsArt:
            item = replace_location_recursive(item, f"{parse_files.migrate_from}", env_inject)
            if item not in parse_files.existingAuthPolFragments:
                POST_Bodies["authPolicyFragments"].append(item)
            else:
                PUT_IDs["authPolicyFragments"].append(item["id"])
                PUT_Bodies["authPolicyFragments"].append(item)
    else:
        POST_Bodies["authPolicyFragments"] = replace_location_recursive(parse_files.authPolFragmentsArt,
                                                                        f"{parse_files.migrate_from}",
                                                                        env_inject)


# Flesh this out
def prepare_keyPair_operations():
    cert_list = []
    file_path = os.getcwd()
    final_path = os.path.join(file_path, r'artifactsPull')
    cert_path = os.path.join(final_path, r'certs')
    encryption_pass = parse_files.get_secret('encryption-cert-pass')["encryptionPass"]
    for file in os.listdir(cert_path):
        with open(os.path.join(cert_path, file)) as f:
            cert_list.append(f.read())
    for i in range(0, len(parse_files.keyPairsArt['items'])):
        POST_Bodies["keyPairs"].append({"id": parse_files.keyPairsArt['items'][i]['id'],
                                        "fileData": "",
                                        "format": "PEM",
                                        "password": f"{encryption_pass}"
                                        })
        POST_Bodies["keyPairs"][i]["fileData"] = cert_list[i]


def replace_location_recursive(data, target_substring, replacement):
    if isinstance(data, str):
        return data.replace(target_substring, replacement)
    elif isinstance(data, list):
        return [replace_location_recursive(item, target_substring, replacement) for item in data]
    elif isinstance(data, dict):
        new_dict = {}
        for key, value in data.items():
            new_dict[key] = replace_location_recursive(value, target_substring, replacement)
        return new_dict
    else:
        return data


def inject_secret_values(d, old_key, new_key, new_value):
    if isinstance(d, dict):
        new_dict = {}
        for key, value in d.items():
            if key == old_key:
                new_dict[new_key] = new_value
            else:
                new_dict[key] = inject_secret_values(value, old_key, new_key, new_value)
        return new_dict
    elif isinstance(d, list):
        new_list = []
        for item in d:
            new_list.append(inject_secret_values(item, old_key, new_key, new_value))
        return new_list
    else:
        return d


prepare_PCV_operations()
prepare_SP_operations()
prepare_client_operations()
prepare_accessTokenManager_operations()
prepare_accessTokenMappings_operations()
prepare_dataStore_operations()
prepare_idpAdapter_operations()
prepare_authPolicyContract_operations()
prepare_authPolicyFragments_operations()
prepare_authPolicy_operations()
prepare_keyPair_operations()
print('Bodies of PUT/POST have been completed.')
print(f'\n\n\nPOST Bodies object are as follows: \n\n\n{json.dumps(POST_Bodies, indent=2)}\n\n\n')
print(f'PUTs look like this: \n\n\n {json.dumps(PUT_Bodies, indent=2)}\n\n\n')
