#!/bin/sh
echo "WE'RE ABOUT TO STOP RIGHT NOW !"
# seal vault
ps | grep "python" | awk '{print $1}' | head -1 | xargs kills
echo "Everything is properly stopped, we can exit"
rm -f /tmp/letitrun
