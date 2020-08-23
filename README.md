# Loxodonta! 

Disect and visualize network traffic like never before.
Loxodonta simplifies network traffic and creates entities and connects them using the metadata of network packets.

# Database
The only database connector currently available is Neo4j, the use of nodes and relationships makes it the natural choice for visualizing data gathered about computers and services on a network.
you can easily set one up - using docker.

## Command line interface
loxo_config  - configure Loxodonta from the command line.
loxo - The pcap digestion tool that does most of the magic.

for example:
```loxo -tand my_sniff_snoff.pcap```

## installation
```
git clone https://github.com/tomerwald/Loxodonta.git
pip3 install Loxodonta
loxo_config -v
 ```