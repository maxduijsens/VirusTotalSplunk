# VirusTotalSplunk
Bash script to export md5 hashes from Splunk and lookup VirusTotal scan results via a Python script.

- Configure the md5_export.sh script with your own Splunk query. This script must be located on the Splunk Indexer.
- Change props.conf and transports.conf with your own values. Help can be found in the Splunk docs.
- Configure your VirusTotal API key in vtsearch.py and if needed remove the time.sleep() call if you have an API key which allows unlimited requests :-)
- Copy the props.conf and transports.conf into your $SPLUNKHOME/etc/system/local/ (make sure not to overwrite any existing files!)
- Crontab md5_export.sh every 30 mins.

It will create two files, md5hashes_30m.txt in the default config, containing all md5 hashes of the last 30minutes
exported from Splunk. It will also create md5_seen.txt containing a list of all md5's it has looked up previously.

Output will be sent to /opt/splunk/etc/system/lookups/vtlookup.csv so make sure to change that path in vtsearch.py if you want the lookup table
to be located elsewhere.

In splunk, any events matching the query set in props.conf will be automagically augmented with vt_* fields containing the
scan results.

# Credits
Based on Didier Stevens' vtsearch script.
