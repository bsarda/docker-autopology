#!/bin/sh
docker ps -a | grep bsarda/autopology | awk '{print $1}' | xargs -n1 docker rm -f
docker rmi bsarda/autopology
docker build --no-cache -t bsarda/autopology .
