#!/bin/bash

if (( $# < 2 )); then
    exit 1
fi

exist_ssid=`nmcli connection show | grep wifi | awk '{print $1}'`

if [ "$exist_ssid" != "" ]; then
    nmcli connection delete $exist_ssid
fi

new_ssid=`nmcli device wifi list | grep -w $1 | awk '{print $1}'`

if [ "$new_ssid" = "$1" ]; then
    nmcli device wifi connect $new_ssid password $2
fi

