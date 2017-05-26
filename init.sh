#!/bin/bash
touch /tmp/letitrun
echo "Starting the container"

# if already initialized or not
if [ ! -f /var/local/autopology ]; then
  # Alpine: adduser -D -s /bin/nologin -H $USERNAME
  # CentOS:
  adduser -s /bin/nologin -N -M $USERNAME
  echo "$USERNAME:$PASSWORD"|chpasswd
  touch /var/local/autopology;
  echo "Local account created"
fi

# start the server
autopology.server >& /var/log/autopology
# wait 5 seconds to start
sleep 5
# echo the log for docker logs usage
cat /var/log/autopology
# check if it's started or not
if [ $(cat /var/log/autopology | grep Failed | wc -l) -gt 0 ]; then
  echo "*** There was an error - exiting. ***"
  # get the error number
  #errorNumber=$((cat /var/log/autopology | grep Errno) | sed 's/.*Errno[[:space:]]//' | sed 's/\].*//')
  rm /tmp/letitrun
  exit 1;
fi

# wait in an infinite loop for keeping alive pid1
trap '/bin/sh -c "/usr/local/bin/stop.sh"' SIGTERM
while [ -f /tmp/letitrun ]; do sleep 1; done
exit 0;
