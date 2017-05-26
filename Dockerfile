# written by Benoit Sarda
# base for containers - uses supervisor to start multiple services.
#
#   bsarda <b.sarda@free.fr>
#
FROM centos:centos7.2.1511
MAINTAINER Benoit Sarda <b.sarda@free.fr>

EXPOSE 443

ENV MANAGER_IP=nsxman01 \
    MANAGER_USERNAME=admin \
    MANAGER_PASSWORD=VMware1! \
    USERNAME=admin \
    PASSWORD=VMware1! \
    ESX_PASSWORD=VMware1! \
    KVM_PASSWORD=P@ssw0rd

COPY ["init.sh","stop.sh","autopology-1.0.20170427-py2-none-any.whl","server.py","/tmp/"]

# RUN apk add --no-cache python py-pip python-dev py-libvirt openssl-dev libffi-dev gcc linux-headers musl-dev libxml2-dev libxslt-dev linux-pam-dev
RUN yum install -y epel-release && yum install -y python python-pip libvirt-python openssl-devel python-devel libffi-devel gcc libxml2-devel libxslt-devel openssh-clients && \
    mv /tmp/init.sh /usr/local/bin/init.sh && mv /tmp/stop.sh /usr/local/bin/stop.sh && \
    chmod 750 /usr/local/bin/init.sh && chmod 750 /usr/local/bin/stop.sh && \
    pip install /tmp/autopology-1.0.20170427-py2-none-any.whl && \
    cp /usr/lib/python2.7/site-packages/autopology/server.py /usr/lib/python2.7/site-packages/autopology/server.py.bak && \
    cp /tmp/server.py /usr/lib/python2.7/site-packages/autopology/server.py -f

CMD ["/usr/local/bin/init.sh"]
