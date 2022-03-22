#!/bin/bash

which docker && docker -v && docker build -t tawny-ctidev . && docker run -v $(pwd):/usr/src/app tawny-ctidev && exit
which podman && podman -v && podman build -t tawny-ctidev . && podman run -v $(pwd):/usr/src/app tawny-ctidev && exit
