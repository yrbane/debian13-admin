#!/bin/bash

sudo awk '
  $0 ~ /^--.*-A--$/ {
    getline
    if (match($0, /([0-9]{1,3}\.){3}[0-9]{1,3}/, m)) print m[0]
  }
' /var/log/apache2/modsec_audit.log \
| sort | uniq -c | sort -nr \
| awk '{print $2}' \
| grep -v -E '^(90\.114\.131\.138|89\.83\.35\.79)$' \
| sort -u \
| xargs -r -n1 sudo ufw deny from

