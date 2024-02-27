FROM docker.repo.local.sfdc.net/sfci/docker-images/sfdc_rhel9:48

COPY ./rpm-generated/*.rpm /tmp/rpm-generated
RUN yum -y localinstall $(find /tmp/rpm-generated -name "*.rpm" | head -n1) && rm /tmp/rpm-generated/*

ENTRYPOINT ["/usr/bin/tacrustd"]
