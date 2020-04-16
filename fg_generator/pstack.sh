#!/bin/bash
 
SPLUNK_HOME=/opt/splunk
OUTPUT_DIR=/tmp/splunk_pstacks
SAMPLES=10
SAMPLE_PERIOD=3
mkdir -p $OUTPUT_DIR
i=0
while [ $i -lt $SAMPLES ]
do
    pstack `head -1 $SPLUNK_HOME/var/run/splunk/splunkd.pid` > $OUTPUT_DIR/pstack_splunkd-$i-`date +%s`.out
    let "i+=1"
    sleep $SAMPLE_PERIOD
done
