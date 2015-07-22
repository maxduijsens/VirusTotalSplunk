#!/bin/bash
# By Max, july-2015
/opt/splunk/bin/splunk search "source="mhn-splunk.log" AND md5 != None | dedup md5 | table md5" -minutesago 30 -output csv > md5hashes_30m.txt
python vtsearch.py md5hashes_30m.txt
