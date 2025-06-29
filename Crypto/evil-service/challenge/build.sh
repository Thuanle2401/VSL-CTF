#!/bin/bash

# Build the Docker image
docker build -t trust-urself .

# Run the Docker container
docker run -d -p 9000:1337 trust-urself