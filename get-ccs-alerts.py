"""
The Resource Name (Repo), the policy violation (both default and custom), severity of the policy, errorID, date, author, status.
"""
import csv
import json
import sys
import os
import time
import requests as req

api = ''

"""
Check the result of a restful API call
"""
def result_ok(result, message):
    if ( not result.ok ):
        print(message)
        result.raise_for_status()

"""
Authenticate against Prisma cloud. Return authentication JWT token
"""
def auth_prisma():
    global api
    api = os.getenv('PRISMA_API_URL')
    username = os.getenv('PRISMA_ACCESS_KEY_ID')
    password = os.getenv('PRISMA_SECRET_KEY')
    if ( api is None or username is None or password is None):
        print('Missing environment variables')
        sys.exit(1)

    payload = { 'username': username, 'password': password }
    headers = { 'Content-Type': 'application/json; charset=UTF-8', 'Accept': 'application/json; charset=UTF-8' }

    result = req.post(f"{api}/login", data=json.dumps(payload), headers=headers)
    result_ok(result,'Could not authenticate to Prisma.')

    return result.json()['token']

"""
Checks on the status of a CSV report download job. Returns a result object from the RESTful call.
"""
def check_report_status(jobid, headers):
    result = req.get(f"{api}/alert/csv/{jobid}/status", headers=headers)
    result_ok(result, f"Could not check the status of the CSV export job {jobid}")
    return result

"""
Renews existing token. Returns new token to use.
"""
def extend_token(mytoken):
    headers =  {'Accept': 'application/json; charset=UTF-8','x-redlock-auth': mytoken}
    result = req.get(f"{api}/auth_token/extend", headers=headers)
    result_ok(result, 'Could not extend current token.')
    return result.json()['token']

"""
Create headers for the RESTful API calls, returns a headers object.
"""
def create_headers(token):
    return { 'Content-Type': 'application/json; charset=UTF-8', 'Accept': 'application/json; charset=UTF-8','x-redlock-auth': token}

"""
Retrieve all CCS alerts
"""
def get_ccs_alerts():
    token = auth_prisma()
    headers = create_headers(token)

    # Get all build policies
    result = req.get(f"{api}/v2/policy?policy.type=config&policy.subtype=build", headers=headers)
    result_ok(result,'Could not get build policies.')

    build_policies = result.json()
    print('Writing build_policies.json')
    with open('build_policies.json', 'w') as outfile:
        outfile.write(json.dumps(build_policies))

    # Start a CSV alert report for the last 7 days
    payload = {"timeRange":{"type":"relative","value":{"amount":7,"unit":"day"}}}
    result = req.post(f"{api}/alert/csv", headers=headers, data=json.dumps(payload))
    result_ok(result, "Could not start a CSV alert report.")
    csvjobid = result.json()['id']
    print(f"CSV Job {csvjobid} started.")

    # Check if report is ready to be downloaded
    result = check_report_status(csvjobid, headers)
    i = 0
    while (i < 20 and result.json()['status'] != 'READY_TO_DOWNLOAD' ):
        result = check_report_status(csvjobid, headers)
        i = i + 1
        time.sleep(2)
        if( i % 4 == 0):
            print('Extending token.')
            token = extend_token(token)
            headers = create_headers(token)

    if (result.json()['status'] == 'READY_TO_DOWNLOAD'):
        dl_filename = f"alerts-{time.strftime('%Y-%m-%dT%H:%M:%S')}.csv"
        print (f"Downloading {dl_filename} report.")
        result = req.get(f"{api}/alert/csv/{csvjobid}/download", headers={'x-redlock-auth': token})
        result_ok(result, f"Could not download CSV report for job {csvjobid}.")
        with open(dl_filename, 'wb') as dl_file:
            dl_file.write(result.content)
    else:
        print(f"CSV report is still being prepared. Download it at {api}/alert/jobs/{csvjobid}/download")
 
    # read the build policies
    build_policies = []
    with open('build_policies.json', 'r') as bpinfile:
        build_policies = json.loads(bpinfile.read())

    alerts = []
    # get a CSV reader for the active alerts
    with open(dl_filename, 'r') as ainfile:
        areader = csv.DictReader(ainfile)
        for r in areader:
            if(r['Alert Status'] == 'open' and r['Policy Type'] == 'config'):
                alerts.append(r)
    # Match policies to alerts if available and add to each row
    print('Alert ID, Policy Name, Policy ID')
    for r in alerts:
        pid = 'N/A'
        x = [i for i in build_policies if i['name'] == r['Policy Name']]
        if(len(x) > 0):
            pid = x[0]['policyId']
        print(f"{r['Alert ID']}, {r['Policy Name']}, {pid}")


if __name__ == '__main__':
    print('Get CCS alerts 0.0.1')
    get_ccs_alerts()
    print('Done')
