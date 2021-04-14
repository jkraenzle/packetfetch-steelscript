import getpass
import argparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings (InsecureRequestWarning)

# SteelScript
import os
os.environ['AR11_ADVANCED_FEATURES']="True"

from steelscript.appresponse.core.appresponse import AppResponse
from steelscript.common import UserAuth
from steelscript.appresponse.core.reports import DataDef, Report
from steelscript.appresponse.core.types import Key, Value, TrafficFilter
from steelscript.appresponse.core.reports import SourceProxy
from steelscript.appresponse.core.types import TimeFilter

SEARCH_TYPE_IPADDRESS = "ipaddr"
SEARCH_TYPE_IPCONVERSATION = "ipconv"
SEARCH_TYPE_OPTIONS = { SEARCH_TYPE_IPADDRESS, SEARCH_TYPE_IPCONVERSATION }

def authenticate (host, username, password):
	ar = AppResponse (host, auth=UserAuth (username, password))
	return ar

# Record format is [<ar>, "hostname", [(tuple), (tuple)]]

def report_record_print (index, record, search_type = SEARCH_TYPE_IPADDRESS):
	print ("%d\t%s\t%s bytes" % (index, record ['hostname'], record ['byte_count'])) 
	return

def report_record_value (record, search_type = SEARCH_TYPE_IPADDRESS):
	return record ['byte_count']

def report_records_summarize (report_data, search_type, search_objects):

	packet_count = 0
	byte_count = 0
	for data_point in report_data:
		if (search_type == SEARCH_TYPE_IPADDRESS):
			packet_count += data_point [2]
			byte_count += data_point [3]
		else:
			packet_count += data_point [2]
			byte_count += data_point [3]

	return packet_count, byte_count

def report_records_enumerate (records, search_type = SEARCH_TYPE_IPADDRESS):
	values = []
	for record in records:
		values.append (report_record_value (record, search_type))
	return values

def report_columns_create (search_type, search_objects):

	columns = [Key ('srv_tcp.ip'), Key ('cli_tcp.ip'), Value ('sum_traffic.packets'), Value ('sum_traffic.total_bytes')]	

	return columns

def report_filter_str_create (search_type, search_objects):
	if (search_type == SEARCH_TYPE_IPADDRESS):
		report_filters = "srv_tcp.ip == " + search_objects [0] + " or cli_tcp.ip == " + search_objects [0]
	else:
		report_filters = "(cli_tcp.ip == " + search_objects [0] + " and srv_tcp.ip == " + search_objects [1] + ") or (cli_tcp.ip == " + search_objects [1] + " and srv_tcp.ip == " + search_objects [0] + ")" 
	
	return report_filters

def find (ar, columns, filter_str, timerange = None, topbycolumns=None):
        # Report
        source = SourceProxy (name='flow_ip')

        data_def = DataDef (source=source, columns=columns, time_range=timerange, topbycolumns=topbycolumns)
        data_def.add_filter (TrafficFilter (filter_str))

        report = Report (ar)
        report.add (data_def)
        report.run ()

        data = report.get_data ()
        headers = report.get_legend ()

        report.delete ()

        return data

def capture_job_list (ar):

	# Show capture jobs
	headers = ['id', 'name', 'filter', 'state', 'start_time', 'end_time', 'size']
	data = []
	for job in ar.capture.get_jobs():
	    data.append({"id":job.id, "name":job.name,
			"filter": getattr(job.data.config, 'filter', None),
			"state": job.data.state.status.state,
			"start_time": job.data.state.status.packet_start_time,
			"end_time": job.data.state.status.packet_end_time,
			"size": job.data.state.status.capture_size})

	return data

def export_filter_create (search_type, search_objects):
	if (search_type == SEARCH_TYPE_IPADDRESS):
		export_filters = [{"id":"f1", "type":"STEELFILTER", "value":"ip.addr==" + search_objects [0]}]
	else:
		export_filters = [{"id":"f2", "type":"STEELFILTER", "value":"ip.addr==" + search_objects [0] + \
			 " and ip.addr==" + search_objects [1]}]

	return export_filters

def export (ar, job_name, filters, timerange = None, filename = None):

	source = ar.capture.get_job_by_name (job_name)
	if (filename == None):
		filename = job_name + "_export.pcap"

	timefilter = TimeFilter (time_range = timerange)

	with ar.create_export (source, timefilter, filters) as e:
		print ("Downloading to file {}".format (filename))
		e.download (filename, overwrite=True)
		print ("Finished downloading to file {}".format (filename))

	return

# General commands

# Helper function to get list of hostnames from input
def hostnamelist_get (hostnamelist):
	hostnamelist_f = open (hostnamelist, "r")

	output = []
	for row in hostnamelist_f:
		hostname = row.rstrip()
		output.append (hostname)

	hostnamelist_f.close ()

	return output

def insert_sorted (sorted_list, new_item):

	values = report_records_enumerate (sorted_list)

	index = 0
	inserted = False
	for value in values:
		if value > report_record_value (new_item):
			sorted_list.insert (index, new_item)
			inserted = True
			break
		index += 1

	if (inserted == False):
		sorted_list.append (new_item)

	return

def main ():

	parser = argparse.ArgumentParser (description="SteelScript utility to search and download packets in AppResponse")
	parser.add_argument('--hostname', help="Hostname or IP address of the AppResponse 11 appliance")
	parser.add_argument('--hostnamelist', help="File containing hostnames or IP addresses, one per line")
	parser.add_argument('--username', help="Username for the appliance")
	parser.add_argument('--searchtype', help="ipaddr or ipconv")
	parser.add_argument('--searchobjects', help="IP address in format x.x.x.x or IP conversation in format <x.x.x.x-y.y.y.y>")
	parser.add_argument('--timerange', help="Time range to analyze (defaults to 'last 1 hour'). Valid formats are "
				"'03/05/20 12:00:00 to 03/06/20 19:53:00'"
				"or '17:09:00 to 18:09:00'"
				"or 'last 14 minutes'")
	parser.add_argument('--filename', help="Filename for packet capture export")
	args = parser.parse_args()

	# Check inputs for required data and prep variables
	if (args.hostname == None or args.hostname == "") and (args.hostnamelist == None or args.hostnamelist == ""):
		print ("Please specify a hostname using --hostname or a list of hostnames in a file using --hostnamelist")
		return
	if (args.username == None or args.username == ""):
		print ("Please specify a username using --username : ")
		return
	print ("Please provide password for account %s" % args.username)
	password = getpass.getpass ()

	# Use either hostname or hostname list; if both are accidentally specified, use hostname list
	if not(args.hostname == None or args.hostname == ""):
		hostnamelist = [args.hostname]
	elif not(args.hostnamelist == None or args.hostnamelist == ""):
		hostnamelist = hostnamelist_get (args.hostnamelist)

	if (args.searchtype != SEARCH_TYPE_IPADDRESS) and (args.searchtype != SEARCH_TYPE_IPCONVERSATION):
		print ("Please specify a search type of ipaddr or ipconv")
		return
	
	search_type = args.searchtype
	search_objects = args.searchobjects.split ('-')
	
	if (args.timerange == None or args.timerange == ""):
		print ("Please specify a time range")
		return

	timerange = args.timerange

	# Loop through hosts, searching for which appliances have search criteria
	columns = report_columns_create (search_type, search_objects) 
	filter_str = report_filter_str_create (search_type, search_objects)

	hits = []
	for hostname in hostnamelist:

		try:
			# Authenticate
			ar = authenticate (hostname, args.username, password)
		except:
			print ("Login failed for %s" % hostname)
			continue		

		# Is IP address a top talker?
		report_data = find (ar, columns, filter_str, timerange)

		if (len (report_data) > 0):
			# Summarize into one record
			packet_count, byte_count = report_records_summarize (report_data, search_type, search_objects) 

			if (len (hits) == 0):
				hits.append ({"authobj":ar, "hostname":hostname, "packet_count":packet_count, "byte_count":byte_count})
			else:
				insert_sorted (hits, {"authobj":ar, "hostname":hostname, "packet_count":packet_count, "byte_count":byte_count})

	# Display the appliances that have the traffic
	if (len (hits) > 0):
		print ("The following AppResponse appliances saw packets that met the search criteria!")

		hit_no = 1
		for hit in hits:
			report_record_print (hit_no, hit, search_type)
			hit_no += 1
		print ("Enter the AppResponse number from which to download packets and hit return > ", end="")
		ar_no = input ()
 
		ar_to_download = hits [int (ar_no) - 1]["authobj"]
	else:
		print ("The search did not find any packets.")
		return

	try:
		# Get Capture Jobs from appliance
		capture_jobs = capture_job_list (ar_to_download)
	except:
		print ("The Capture Jobs for the selected appliance could not be retrieved.")
	
	if (len (capture_jobs) > 0):
		# Ask the user which Capture Job should be used
		job_no = 1
		for job in capture_jobs:
			print ("%d:\t%s\t%s" % (job_no, job ["name"], job ["state"]))
			job_no += 1

		print ("Enter the Capture Job number from which to download packets and hit return > ", end='')
		job_no = input ()
		job_name = capture_jobs [int (job_no) - 1]["name"]

		export_filters = export_filter_create (search_type, search_objects)
		export (ar_to_download, job_name, export_filters, timerange, filename=args.filename)

	return
 
if __name__ == "__main__":
	main ()
