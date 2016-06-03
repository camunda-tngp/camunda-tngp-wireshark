# Camunda TNGP Protocol Wireshark Dissector

## Requirements

- Wireshark with Lua Support (Lua >= 5.2)

## Install

### Linux

```
mkdir -p ~/.wireshark/plugins/
git clone git@github.com:camunda-tngp/camunda-tngp-wireshark.git ~/.wireshark/plugins/camunda-tngp-wireshark
```

### Docker

```
# build docker image
docker build -t tshark .

# run tshark with linked pcap file
docker run --rm -v $PWD/tngp.pcap:/tngp.pcap tshark -r /tngp.pcap

# only outputs transport requests with the timestamp, request id and type
docker run --rm -v $PWD/tngp.pcap:/tngp.pcap tshark -r /tngp.pcap -T fields -e frame.time_epoch -e tngp.transport.request.request -e tngp.transport.request.type tngp.transport.request.request!=0
```



## Screenshot

![Wireshark dissecting Camunda TNGP protocol](/screenshot.png?raw=true "Wireshark dissecting Camunda TNGP protocol")
