# packetfetch-steelscript

To setup the Python 3 environment, install:
pip install git+https://github.com/riverbed/steelscript
pip install git+https://github.com/riverbed/steelscript-appresponse
git clone https://github.com/jkraenzle/packetfetch-steelscript

# fetch.aggregates.py
# fetch.flow_tcp.py/fetch.flow_ip.py
The usage for fetch.aggregates.py and fetch.flow_tcp.py/fetch.flow_ip.py is identical:

usage: fetch.<>.py [-h] [--hostname HOSTNAME]
                         [--hostnamelist HOSTNAMELIST] [--username USERNAME]
                         [--searchtype SEARCHTYPE]
                         [--searchobjects SEARCHOBJECTS]
                         [--timerange TIMERANGE] [--filename FILENAME]

SteelScript utility to search and download packets in AppResponse

optional arguments:
  -h, --help            show this help message and exit
  --hostname HOSTNAME   Hostname or IP address of the AppResponse 11 appliance
  --hostnamelist HOSTNAMELIST
                        File containing hostnames or IP addresses, one per
                        line
  --username USERNAME   Username for the appliance
  --searchtype SEARCHTYPE
                        ipaddr or ipconv
  --searchobjects SEARCHOBJECTS
                        IP address in format x.x.x.x or IP conversation in
                        format <x.x.x.x-y.y.y.y>
  --timerange TIMERANGE
                        Time range to analyze (defaults to 'last 1 hour').
                        Valid formats are '03/05/20 12:00:00 to 03/06/20
                        19:53:00'or '17:09:00 to 18:09:00'or 'last 14 minutes'
  --filename FILENAME   Filename for packet capture export

From the output at the command line:

(steelscript) C02WG1MYHV2Q-MAC:steelscript $ python fetch.flow_tcp.py --hostname 10.1.150.220 --username admin --searchtype ipconv --searchobjects 10.1.150.234-10.1.150.232 --timerange '20:00:00 to 20:01:00' --filename test.pcap
Please provide password for account admin
Password: xxxxxxx
The following AppResponse appliances saw packets that met the search criteria!
1:       10.1.150.220         1720155 bytes
Enter the AppResponse number from which to download packets and hit return > 1
1 : Capture DNS RUNNING
2 : NewCaptureJob STOPPED
3 : Capture Everything RUNNING
4 : Capture Critical Web App RUNNING
5 : Test for ABC STOPPED
Enter the Capture Job number from which to download packets and hit return > 3
Downloading to file test.pcap
Finished downloading to file test.pcap

Now, there’s caveats to the three ‘sources’ and the three scripts:
aggregates – Topped, so if the IP address falls outside of the range then you are not going to get the data
flow_tcp – Not officially supported, and only includes TCP conversations. It is the HD data source so doesn’t top, but has a shorter history.
flow_ip – Officially supported in 11.9. Same as flow_tcp but includes non-TCP, IP-based conversations.

# download.layer-2.py

The script download.layer-2.py quick example of using the REST API to get the packet capture.

To run the command, use:
    python3 download.layer-2.py --hostname <hostname> --username <username> [--password <password>] --timerange 'last 30 min' --filter 'arp'

If the password is not provided on the command line, it will be requested as the script runs.

The ‘filter’ for this script only accepts Wireshark filter types that would be put at the top of Wireshark UI.

The command should download a pcap file per Capture Job on the specified appliance.

