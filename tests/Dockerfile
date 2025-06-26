FROM rpm-tests as src
MAINTAINER jakuje@gmail.com

WORKDIR /srv/rpm
COPY /target/debug/librpm_sequoia.so /usr/local/lib64/
COPY /target/debug/librpm_sequoia.so.1 /usr/local/lib64/
RUN ldconfig
