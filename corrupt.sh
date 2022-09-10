#!/bin/bash

trap "exit" INT
for i in {0..9} {A..F}; do
    end=`echo "obase=ibase=16;${1}${i}${3}+1" | bc`
    echo -n "sequence ${i}-${end}: "
    ./snes-rom-corruptor -i ~/Downloads/FFMQR_1.2.02_B45F3F05_OwzmHQAAAAA~.sfc -o ~/Downloads/ffmq.sfc -s ${1}${i}${2} -e ${end} -m up -v 1  && zsnes ~/Downloads/ffmq.sfc &> /dev/null
done
