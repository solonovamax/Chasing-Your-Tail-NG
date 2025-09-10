#!/usr/bin/env bash

timeout_count=0
while ! xset q &>/dev/null; do
    echo "$(date): Waiting for X server... (attempt $timeout_count)" >> gui_startup.log

    sleep 15

    timeout_count=$((timeout_count + 1))

    if [ $timeout_count -gt 20 ]; then
        echo "$(date): ERROR - X server timeout after 300 seconds" >> gui_startup.log
        exit 1
    fi
done

echo "$(date): X server available, starting GUI..." >> gui_startup.log

# Start the GUI and log any output
python3 cyt_gui.py >> gui_startup.log 2>&1 &

# Log success
echo "$(date): CYT GUI started successfully" >> gui_startup.log