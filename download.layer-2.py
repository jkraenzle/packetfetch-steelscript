import argparse
import getpass
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SteelScript
import os
os.environ['AR11_ADVANCED_FEATURES']="True"

from steelscript.common.exceptions import RvbdHTTPException
from steelscript.appresponse.core.appresponse import AppResponse
from steelscript.common import UserAuth
from steelscript.appresponse.core.reports import SourceProxy
from steelscript.appresponse.core.types import TimeFilter

def authenticate(host, username, password):
	ar = AppResponse(host, auth=UserAuth(username, password))
	return ar

def capture_job_list(ar):
	
	headers = ['id', 'name', 'filter', 'state', 'start_time', 'end_time', 'size']
	data = []
	for job in ar.capture.get_jobs():
		data.append({'id':job.id, 'name':job.name, 'filter': getattr(job.data.config, 'filter', None),
			'state':job.data.state.status.state, 'start_time':job.data.state.status.packet_start_time,
			'end_time':job.data.state.status.packet_end_time, 'size':job.data.state.status.capture_size})

	return data

def export_filter_create(filter=None):
	if filter == None:
		export_filters = [{'id':'f1', 'type':'WIRESHARK', 'value':'not ip'}]
	else:
		export_filters = [{'id':'f1', 'type':'WIRESHARK', 'value':str(filter)}]

	return export_filters

def export(ar, job_name, filters, timerange=None, folder=None):

	source = ar.capture.get_job_by_name(job_name)
	info = ar.get_info()
	hostname = info['device_name']

	filename = hostname + '_' + job_name + "_export.pcap"
	if folder != None:
		filename = folder + filename

	timefilter = TimeFilter(time_range=timerange)

	try:
		with ar.create_export(source, timefilter, filters) as e:
			print("Downloading to file {}".format(filename))
			e.download(filename, overwrite=True)
			print("Finished downloading to file {}".format(filename))
	except RvbdHTTPException as e:
		print(e)
	except:
		print(sys.exc_info()[0])
		print(f"Failed to download packets from {job_name} on appliance {hostname}")

	return

# General commands

# Helper function to get list of hostnames from input
def hostnamelist_get(hostnamelist):
	hostnamelist_f = open(hostnamelist, "r")

	output = []
	for row in hostnamelist_f:
		hostname = row.rstrip()
		output.append(hostname)

	hostnamelist_f.close()

	return output

def insert_sorted(sorted_list, new_item):

	values = report_records_enumerate(sorted_list)

	index = 0
	inserted = False
	for value in values:
		if value > report_record_value(new_item):
			sorted_list.insert(index, new_item)
			inserted = True
			break
		index += 1

	if(inserted == False):
		sorted_list.append(new_item)

	return

def main():

	parser = argparse.ArgumentParser(description="SteelScript utility to search and download packets in AppResponse")
	parser.add_argument('--hostname', help="Hostname or IP address of the AppResponse 11 appliance")
	parser.add_argument('--hostnamelist', help="File containing hostnames or IP addresses, one per line")
	parser.add_argument('--username', help="Username for the appliance")
	parser.add_argument('--password', help="Password for provided username")
	parser.add_argument('--filter', help="Wireshark filter")
	parser.add_argument('--timerange', help="Time range to analyze(defaults to 'last 1 hour'). Valid formats are "
				"'03/05/20 12:00:00 to 03/06/20 19:53:00'"
				"or '17:09:00 to 18:09:00'"
				"or 'last 14 minutes'")
	parser.add_argument('--folder', help="Folder for packet capture export")
	args = parser.parse_args()

	# Check inputs for required data and prep variables
	if (args.hostname == None or args.hostname == "") and (args.hostnamelist == None or args.hostnamelist == ""):
		print("Please specify a hostname using --hostname or a list of hostnames in a file using --hostnamelist")
		return
	if (args.username == None or args.username == ""):
		print("Please specify a username using --username : ")
		return

	if args.password == None:
		print("Please provide password for account %s" % args.username)
		password = getpass.getpass()
	else:
		password = args.password

	# Use either hostname or hostname list; if both are accidentally specified, use hostname list
	if not(args.hostname == None or args.hostname == ""):
		hostnamelist = [args.hostname]
	elif not(args.hostnamelist == None or args.hostnamelist == ""):
		hostnamelist = hostnamelist_get(args.hostnamelist)

	if(args.timerange == None or args.timerange == ""):
		print("Please specify a time range")
		return

	timerange = args.timerange

	# Find which hostnames allow valid logins
	valid_ars = []
	for hostname in hostnamelist:

		try:
			# Authenticate
			ar = authenticate(hostname, args.username, password)
		except:
			print("Login failed for %s" % hostname)
			continue		

		if len(valid_ars) == 0:
			valid_ars.append({'authobj':ar, 'hostname':hostname})
		else:
			insert_sorted(valid_ars, {'authobj':ar, 'hostname':hostname})

	# Display the appliances that have the traffic
	if len(valid_ars) == 0:
		return

	for valid_ar in valid_ars:
		ar_to_download = valid_ar['authobj']

		try:
			# Get Capture Jobs from appliance
			capture_jobs = capture_job_list(ar_to_download)
		except:
			ar_to_download_hostname = valid_ar['hostname']
			print(f"The Capture Jobs for the selected appliance {ar_to_download_hostname} could not be retrieved.")
	
		if len(capture_jobs) > 0:
			for job in capture_jobs:
				job_name = job['name']

				export_filters = export_filter_create(args.filter)
				export(ar_to_download, job_name, export_filters, timerange, folder=args.folder)


	return
 
if __name__ == "__main__":
	main()
