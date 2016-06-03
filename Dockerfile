FROM ubuntu:latest

ENTRYPOINT ["tshark"]

RUN apt-get update && \
    apt-get install -y --no-install-recommends tshark && \
    apt-get clean && \
    rm -rf /var/cache/* /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    useradd -m tshark

USER tshark

COPY camunda-tngp-dissector.lua /home/tshark/.wireshark/plugins/camunda-tngp-wireshark/camunda-tngp-dissector.lua
