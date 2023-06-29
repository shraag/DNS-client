# Project Title: Custom DNS Resolver

## Table of Contents
1. [Overview](#overview)
2. [Setup and Execution](#setup-and-execution)
3. [Code Structure](#code-structure)
4. [Additional Comments](#additional-comments)

## Overview <a name="overview"></a>
This Python script is a custom DNS resolver. It sends a query to a specified DNS resolver and decodes the response to extract meaningful information such as domain name and the corresponding IP address. It is designed to work with DNS servers that support both UDP on port 53 and TCP on port 80.

## Setup and Execution <a name="setup-and-execution"></a>

1. Make sure you have Python 3 installed in your environment. If not, you can download Python [here](https://www.python.org/downloads/).

2. Clone the repository and navigate to the project directory:
    ```bash
    git clone https://github.com/username/DNS-client.git
    cd DNS-client
    ```

3. Run the script with your desired hostname as an argument:
    ```bash
    python3 dns_resolver.py <hostname>
    ```
    > Note: Replace `<hostname>` with the domain name you want to resolve, e.g., "tmz.com".

## Code Structure <a name="code-structure"></a>
The code is composed of various functions that handle different parts of the DNS message creation, transmission, and parsing process:

- `message(url)`: Creates the DNS query message in binary format.
- `send_message(message, address, port)`: Sends the message to the DNS resolver and receives the response.
- `hex_to_binary(string)`: Decodes a hexadecimal string into binary.
- `response_unpack(response)`: Parses the entire DNS response message, extracting meaningful information like domain name and IP address.

## Additional Comments <a name="additional-comments"></a>
You may find sections of the code commented out. These sections were used for testing with different DNS resolvers, calculating the Round Trip Time (RTT), and making a TCP connection to the HTTP server of the resolved IP address. If you wish to use these sections, you can uncomment them and adjust according to your requirements.
