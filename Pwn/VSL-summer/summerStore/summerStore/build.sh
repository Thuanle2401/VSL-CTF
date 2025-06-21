#!/bin/bash

# Build docker image
docker build -t summerstore .

# Run docker container
docker run -d -p 7003:1337 --name summerstore summerstore
