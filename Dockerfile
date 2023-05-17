FROM ubuntu:latest
MAINTAINER Francesco Andronico <andronico.francesco@gmail.com>
LABEL Description="Auto Vulnerability Assessment" \
    License="Innonation"

ENV TZ=Europe/Rome \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        python3 \
        python3-pip \
        python3-protobuf \
        python3-openssl \
        python3-twisted \
        python3-yaml \
        nmap

# Clone the AutoVA repository
RUN git clone https://github.com/franzo9448/Auto_VA.git /tmp/autova

# Set the working directory
WORKDIR /tmp/autova
RUN mkdir openvasreporting

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt && \
    pip3 install --no-cache-dir gvm-tools && \
    pip3 install --no-cache-dir python-owasp-zap-v2.4 && \
    pip3 install --no-cache-dir \
        termcolor \
        pyfiglet \
        pygments \
        json2html


# Copy AutoVA files
ADD openvasreporting /tmp/autova/openvasreporting



