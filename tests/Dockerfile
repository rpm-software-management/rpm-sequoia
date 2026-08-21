FROM rpm-tests
MAINTAINER jjelen@redhat.com

WORKDIR /srv/rpm
COPY /target/debug/librpm_sequoia.so /usr/local/lib64/librpm_sequoia.so.1
RUN ln -s librpm_sequoia.so.1 /usr/local/lib64/librpm_sequoia.so
RUN ls -l /usr/local/lib64/librpm_sequoia*
RUN ldconfig
