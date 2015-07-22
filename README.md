# VirusTotalSplunk
Bash script to export md5 hashes from Splunk and lookup VirusTotal scan results via a Python script.

# Installation
- Configure the md5_export.sh script with your own Splunk query. This script must be located on the Splunk Indexer.
- Change props.conf and transports.conf with your own values. Help can be found in the Splunk docs.
- Configure your VirusTotal API key in vtsearch.py and if needed remove the time.sleep() call if you have an API key which allows unlimited requests :-)
- Copy the props.conf and transports.conf into your $SPLUNKHOME/etc/system/local/ (make sure not to overwrite any existing files!)
- Crontab md5_export.sh every 30 mins.
- Query Splunk to find unknown or non-malicious malware like so: `sourcetype = mhn-splunk-2 vt_found=0 OR vt_detections = 0 | dedup md5 | table md5, vt_total, vt_detections`

It will create two files, md5hashes_30m.txt in the default config, containing all md5 hashes of the last 30minutes
exported from Splunk. It will also create md5seen.txt containing a list of all md5's it has looked up previously.

Output will be sent to /opt/splunk/etc/system/lookups/vtlookup.csv so make sure to change that path in vtsearch.py if you want the lookup table
to be located elsewhere.

In Splunk, any events matching the query set in props.conf will be automagically augmented with vt_* fields containing the
scan results. Note that these fields are not populated live, but rather every 30 minutes so if your events contain new md5 hashes of the previous 30mins 
the results will not be included in the lookup table yet.

# Augmented fields
- vt_date: Last scan date of VirusTotal
- vt_details: Long blob of detections by the different virusscanners
- vt_detections: Amount of detections (out of vt_total)
- vt_total: Amount of virusscanners that scanned this hash
- vt_found: 1 if the hash was found, 0 if it was not found
- vt_url: permalink to the VirusTotal scan result

If vt_found = 0, the vt_date and vt_detections fields will contain a message saying the hash was not amongst the finished queued or pending scans.

# Credits
Based on Didier Stevens' vtsearch script.
