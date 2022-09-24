import intersight
import re
from intersight.api import boot_api
from intersight.model.boot_precision_policy import BootPrecisionPolicy
from intersight.api import boot_api
from intersight.model.boot_precision_policy import BootPrecisionPolicy
from intersight.model.boot_device_base import BootDeviceBase
from intersight.model.organization_organization_relationship import OrganizationOrganizationRelationship
from pprint import pprint
import intersight
from intersight.api import asset_api
import intersight.api.cond_api
import intersight.api.server_api
import intersight.api.view_api
import intersight.api.hyperflex_api
import intersight.api.compute_api
import intersight.api.fabric_api
import json
import requests
from datetime import datetime,timedelta



def get_api_client(api_key_id, api_secret_file, endpoint="https://intersight.com"):
    private_key_path= r"C:\Users\Administrator\Desktop\Intersight\SecretKey.txt"
    key_id='629f4f847564612d335a1c0d/629f4f847564612d335a1c14/62a7a70e7564612d338b9948'
    with open(api_secret_file, 'r') as f:
        api_key = f.read()

    if re.search('BEGIN RSA PRIVATE KEY', api_key):
        # API Key v2 format
        signing_algorithm = intersight.signing.ALGORITHM_RSASSA_PKCS1v15
        signing_scheme = intersight.signing.SCHEME_RSA_SHA256
        hash_algorithm = intersight.signing.HASH_SHA256

    elif re.search('BEGIN EC PRIVATE KEY', api_key):
        # API Key v3 format
        signing_algorithm = intersight.signing.ALGORITHM_ECDSA_MODE_DETERMINISTIC_RFC6979
        signing_scheme = intersight.signing.SCHEME_HS2019
        hash_algorithm = intersight.signing.HASH_SHA256


    configuration = intersight.Configuration(
        host=endpoint,
        signing_info=intersight.signing.HttpSigningConfiguration(
            key_id=key_id,
            private_key_path=private_key_path,
            signing_scheme=signing_scheme,
            signing_algorithm=signing_algorithm,
            hash_algorithm=hash_algorithm,
            signed_headers=[
                intersight.signing.HEADER_REQUEST_TARGET,
                intersight.signing.HEADER_HOST,
                intersight.signing.HEADER_DATE,
                intersight.signing.HEADER_DIGEST,
            ]
        )
    )
    print("I ran")
    return intersight.ApiClient(configuration)
private_key_path= r"C:\Users\Administrator\Desktop\Intersight\SecretKey.txt"
key_id='629f4f847564612d335a1c0d/629f4f847564612d335a1c14/62a7a70e7564612d338b9948'


api_client = get_api_client(key_id, private_key_path)

api_instance= intersight.api.cond_api.CondApi(api_client)

def query_res():
    search_period= datetime.now() - timedelta(days=100)
    date_str= f"{search_period.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z"
    query_filter=f"Severity eq Critical and CreationTime gt {date_str}"
    query_select="CreationTime,Description,Name,OrigSeverity,AffectedMoDisplayName"
    alarm_query= api_instance.get_cond_alarm_list(filter=query_filter,select=query_select)
    alarm_res = alarm_query.results
    return alarm_res


def ivanti(description,creation_time,name,orig_severity,affected_mo_display_name):
    url = "https://vzure2.vantosi.com/HEAT/api/odata/businessobject/incidents"

    payload = json.dumps({
    "ProfileLink_RecID": "2F851094BFE5437C97D19871D1C539C7",
        "Category": "Service Desk",
        "CreatedBy":"Admin",
         "Symptom" : str(name)+str(description),
        "Owner" : "Bo R Heath",
        "Urgency" : "Low",
        "Impact" : "Medium",
        "OwnerTeam":"Corporate Accounts Payable Team",
        "Subject":description,
        "Status":"Active"
    })
    headers = {
      'Authorization': 'rest_api_key=147EFE69551B4037B428D37FE3A3D443',
      'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    
def get_alarms():
    res= query_res()
    for item in res:
        print(item['creation_time'])
        description= item['description']
        creation_time= item['creation_time']
        name= item['name']
        orig_severity= item['orig_severity']
        affected_mo_display_name= item['affected_mo_display_name']

        ivanti(description,creation_time,name,orig_severity,affected_mo_display_name)

        
    
def main():
    get_alarms()
    
main()

#now = datetime.now()-datetime.deltatime(year=12)
#current_time = now.strftime("%Y-%m-%dT%H:%M:%S")
#print(current_time)

#alarm_time=creation.strftime("%Y-%m-%dT%H:%M:%S")
#print(alarm_time)

#if alarm_time<now:
#    print(alarm_time)
#creation


 



'''def creation(creation):
    create = creation.strftime("%Y-%m-%d%H:%M:%S")
    now=datetime.now()
    today8am= now.replace(hour=8,minute=0,second=0,microsecond=0)
    create=datetime.strptime(create,"%Y-%m-%d%H:%M:%S")
    #print(creation)
    #print(today8am)
    search_date=today8am - timedelta(days=30)
    if create> search_date:
        print(create)'''




    











