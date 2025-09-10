#!/usr/bin/env bash

GREEN=$'\e[0;32m'
RED=$'\e[0;31m'
RESET=$'\e[0m'

while true; do
    if [[ $(pgrep -cif 'kismet') -gt 1 ]]; then
        echo "${GREEN}kismet up${RESET}"
    else
        echo "${RED}kismet down${RESET}"
    fi

    # wtf is this doing?
    iwconfig_output=$(iwconfig wlan0 & iwconfig wlan1 & iwconfig wlan1mon)

    if [[ $iwconfig_output == *"Mode:Monitor"* ]]; then
        echo "${GREEN}Monitor Mode Detected${RESET}"
        echo
    else
        echo "${RED}Monitor Mode Not Detected${RESET}"
    fi

    sleep 10
done
