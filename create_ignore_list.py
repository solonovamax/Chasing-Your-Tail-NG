import glob
import json
import os
import sqlite3
from pathlib import Path
from sqlite3 import Connection

from utils import load_config


def sql_fetch(con: Connection):
    cursor = con.cursor()

    cursor.execute("SELECT devmac FROM devices")

    rows = cursor.fetchall()

    for row in rows:
        # why tf does it need to replace all these characters???
        stripped_val = str(row).replace("(", "").replace(")", "").replace("'", "").replace(",", "")
        non_alert_list.append(stripped_val)


def grab_all_probes(con: Connection):
    cursor = con.cursor()
    cursor.execute("SELECT devmac, type, device FROM devices")
    rows = cursor.fetchall()
    for row in rows:
        raw_device_json = json.loads(row[2])
        if 'dot11.probedssid.ssid' in str(row):
            ssid_probed_for = raw_device_json["dot11.device"]["dot11.device.last_probed_ssid_record"]["dot11.probedssid.ssid"]  ### Grabbed SSID Probed for
            if ssid_probed_for == '':
                pass
            else:
                non_alert_ssid_list.append(ssid_probed_for)


config = load_config()

non_alert_list = []
non_alert_ssid_list = []

db_path = config['paths']['kismet_logs']

list_of_files = glob.glob(db_path)
latest_file = max(list_of_files, key=os.path.getmtime)  # get file that has been most recently modified
print('Pulling from: {}'.format(latest_file))

con = sqlite3.connect(latest_file)  ## kismet DB to point at

sql_fetch(con)

print('Added {} MACs to the ignore list.'.format(len(non_alert_list)))

ignore_list_path = Path(config['paths']['ignore_lists']['mac'])
ignore_list_path.parent.mkdir(parents=True, exist_ok=True)
with open(ignore_list_path, "w") as ignore_list:
    ignore_list.write("ignore_list = " + str(non_alert_list))

grab_all_probes(con)

print('Added {} Probed SSIDs to the ignore list.'.format(len(non_alert_ssid_list)))

with open(Path(config['paths']['ignore_lists']['ssid']), "w") as ignore_list_ssid:
    ignore_list_ssid.write("non_alert_ssid_list = " + str(non_alert_ssid_list))
