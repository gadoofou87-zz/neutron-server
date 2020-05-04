# Neutron server

![Build status image](https://circleci.com/gh/gadoofou87/neutron-server/tree/master.svg?style=shield)

Free open source server, written in C++ / Qt

## Disclaimer

This project was created for educational purposes. Not recommended for everyday use.

## Features

- Quantum-secure cryptographic protocol
- Parallelization for all threads
- Using TCP to communicate with a client
- Using PostgreSQL as a database (unencrypted connection) 

## Build instructions
1. Install required components:
- [Qt](https://www.qt.io/)
- [Crypto++](https://github.com/weidai11/cryptopp)
- [liboqs](https://github.com/open-quantum-safe/liboqs)

2. Get the source:
```
git clone https://github.com/gadoofou87/neutron-server
cd neutron-server
```
and build:
```
mkdir build && cd build
cmake ..
cmake --build . --target all
```

## Using
Create a configuration file **server.ini**. Template:
```
[General]
Name=<string>       ; server name
Motd=<string>       ; message of the day (optional)
DbName=<string>     ; database name
DbHost=<string>     ; database hostname
DbPort=<integer>    ; database port
DbUser=<string>     ; username for authentication in the database
DbPass=<string>     ; password for authentication in the database
Port=<integer>      ; port for listening to incoming connections
```

Each time the server starts, it will display its identifier. Tell it to everyone who will connect to the server.
