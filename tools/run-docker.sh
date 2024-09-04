#!/bin/bash

docker run -it --rm -p 8080:8080 --env-file .env annotation-backend-api:latest
