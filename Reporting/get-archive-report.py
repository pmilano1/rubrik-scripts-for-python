import requests
import base64
import sys
import os
import getopt
import getpass
import time
import random
from timeit import default_timer as timer
from multiprocessing.pool import ThreadPool
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
start = timer()
if len(sys.argv) != 3:
    print '***' + sys.argv[0] + ' usage: -n <node IP or hostname>'
    os._exit(1)
myopts, args = getopt.getopt(sys.argv[1:], 'n:')
for opt, opt_value in myopts:
    if opt == '-n':
        node = opt_value

username = raw_input('Username: ')
password = getpass.getpass()
sla = raw_input('SLA Domains (comma delimited, or leave empty for all): ')

# Use Basic Auth Headers
auth_string = base64.b64encode(username + ':' + password)
basic_auth_header = 'Basic ' + auth_string
header = {'Accept': 'application/json', 'Authorization': basic_auth_header}

selected = ["Location", "ObjectName", "ObjectType", "SlaDomain"]

# Static hash of object information
objtype = {
 'VmwareVirtualMachine': {'url': 'v1/vmware/vm/{}/snapshot', 'array': 'data'},
 'Mssql': {'url': 'v1/mssql/db/{}/snapshot', 'array': 'data'},
 'LinuxFileset': {'url': 'v1/fileset/{}', 'array': 'snapshots'},
 'WindowsFileset': {'url': 'v1/fileset/{}', 'array': 'snapshots'},
 'NasFileset': {'url': 'v1/fileset/{}', 'array': 'snapshots'},
 'ManagedVolume': {'url': 'internal/managed_volume/{}/snapshot', 'array': 'data'}
}

# Static Variables
limit = 100
object_report_name = "Object Protection Summary"
filename = "rubrik_archive_report_{}.csv".format(time.strftime("%Y%m%d-%H%M%S"))
threads_per_node = 10


# Progress Bar
def progress(count, total, status=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))
    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
    sys.stdout.write('[%s] %s%s (%s)\r' % (bar, percents, '%', status))
    sys.stdout.flush()
    if count == total:
        sys.stdout.flush()


# Threader
def run_threads(lines, th):
    pool = ThreadPool(len(ips)*th)
    t = len(rr['rd'])
    result = pool.map_async(process_report, lines, chunksize=1)
    while not result.ready():
        progress((t - result._number_left), t, "{} of {}".format(t - result._number_left, t))
    pool.close()
    pool.join()
    return result.get()


# Worker
def process_report(line):
    rubrik_node = random.choice(ips)
    ro = []
    for f in selected:
        ro.append(line[rr['rc'].index(f)])
    ro.append(get_latest_archive_info(rubrik_node, line[rr['rc'].index('ObjectId')], line[rr['rc'].index('ObjectType')]))
    return ro


# Get Cluster Ips to thread against
def get_ips(n):
    r_ips = []
    ip_call = "/api/internal/node"
    ip_uri = ("{}{}".format(n, ip_call))
    ip_request = requests.get(ip_uri, headers=header, verify=False, timeout=15).json()
    for rubrik_node in ip_request['data']:
        if rubrik_node['status'] == "OK":
            r_ips.append("https://{}".format(rubrik_node['ipAddress']))
    return r_ips


# Get Latest Archive, or report None
def get_latest_archive_info(n, id, a):
    archive_call = ("/api/{}".format(objtype[a]['url'].format(id)))
    archive_uri = ("{}{}".format(n, archive_call))
    archive_request = requests.get(archive_uri, headers=header, verify=False, timeout=15).json()
    for snap in archive_request[objtype[a]['array']]:
        if snap['cloudState'] > 0:
            return snap['date']
    return "None"


# Get Object information from Envision
def get_rubrik_objects(n, id, sla):
    total = 0
    found = 0
    out = {}
    page_payload = {'limit': limit}
    page_endpoint = ("/api/internal/report/{}/table".format(id))
    page_uri = ("{}{}".format(n, page_endpoint))
    page_hasmore = True
    page_cursor = False
    while page_hasmore:
        if page_cursor:
            page_payload['cursor'] = page_cursor
        page_call = requests.post(page_uri, headers=header, json=page_payload, verify=False).json()
        page_cursor = page_call['cursor']
        page_hasmore = page_call['hasMore']
        out['rc'] = page_call['columns']
        for dg_line in page_call['dataGrid']:
            total += 1
            if dg_line[page_call['columns'].index('ObjectType')] not in objtype.keys():
                continue
            if dg_line[page_call['columns'].index('SlaDomain')] in sla:
                found += 1
                out.setdefault("rd", []).append(dg_line)
            elif not sla:
                found += 1
                out.setdefault("rd", []).append(dg_line)
            sys.stdout.write("\r")
            sys.stdout.write('Identifying Objects {}/{}'.format(found,total))
            sys.stdout.flush()
    print " Completed"
    return out


# Get the Object Protection Report ID
try:
    node = "https://{}".format(node)
    call = ("/api/internal/report?name={}".format(object_report_name))
    uri = ("{}{}".format(node, call))
    object_report_list = requests.get(uri, headers=header, verify=False, timeout=15).json()
    for object_report in object_report_list['data']:
        if object_report_name == object_report['name']:
            object_report_id = object_report['id']
except Exception as e:
    print "Failed getting Report ID"

if (object_report_id):
    rr = get_rubrik_objects(node, object_report_id, sla)

# Prepare and write column headers
c = selected[:]
c.append("ArchiveDate")
out_file = open(filename,"a")
out_file.write(', '.join('"{0}"'.format(w) for w in c) + "\n")

# Prepare and write final report
print "Getting Object Archive Information "
count = 0
ips = get_ips(node)
out = run_threads(rr['rd'], threads_per_node)
end = timer()
progress(len(rr['rd']), len(rr['rd']), "Completed in {} seconds".format(end - start))
for line in out:
    out_file.write(', '.join('"{0}"'.format(w) for w in line) + "\n")
print("\nFile is {}".format(filename))
out_file.close()

