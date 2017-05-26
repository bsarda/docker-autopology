# docker-autopology
This is the NSX-T Autopology Fling container on CentOS 7.2 1511.  

Sample usage:  
`docker run -d -p 8443:443 --name autopology --env MANAGER_IP=e1f0nsxman01 --env MANAGER_USERNAME=admin --env MANAGER_PASSWORD='eP@N736w4A88!Me#' --env USERNAME=admin --env PASSWORD=VMware1! --env ESX_PASSWORD=phoeniX1 --env KVM_PASSWORD=P@ssw0rd bsarda/autopology`  

The parameters must be correct to be able to run.  

Open the interface from a brower, like https://192.168.63.5:8443  

## Options as environment vars
- MANAGER_IP => NSX-T Manager hostname (must match certificate CN)  
- MANAGER_USERNAME => NSX-T Manager usernane, default 'admin'  
- MANAGER_PASSWORD => NSX-T Manager password, default 'VMware1!'  
- USERNAME => local user to create (will be used to login on the UI), default 'admin'  
- PASSWORD => password of the local user, default 'VMware1!'  
- ESX_PASSWORD => ESXi hosts root password, default 'VMware1!'  
- KVM_PASSWORD => KVM hosts root password, default 'P@ssw0rd'  
