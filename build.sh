#!/bin/bash
docker build -t tawny-ctidev . && docker run -v $(pwd)/output:/usr/src/app/output tawny-ctidev
