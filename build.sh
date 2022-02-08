#!/bin/bash
docker build -t tawny-ctidev . && docker run -v $(pwd):/usr/src/app tawny-ctidev
