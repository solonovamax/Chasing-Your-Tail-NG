### Chasing Your Tail V04_15_22
### @matt0177
### Released under the MIT License https://opensource.org/licenses/MIT
###

import glob
import logging
import os
import signal
import sys
import time
from pathlib import Path

from secure_database import KismetDB
from ignore_list_loader import load_ignore_lists
from secure_main_logic import SecureCYTMonitor
from utils import load_config

config = load_config('config.json')

logs_dir = Path(Path(config['paths']['log_dir'])) / time.strftime("%m-%d-%Y-%H-%M-%S")
logs_dir.mkdir(parents=True, exist_ok=True)

log_file = logs_dir / 'cyt.log'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name): %(message)s',
    handlers=[
        logging.FileHandler(logs_dir / 'cyt.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

event_log_file = logs_dir / 'probes' / f'events.jsonl'

cyt_log = open(log_file, "w", buffering=1)
event_log = open(event_log_file, buffering=1)

#######Load ignore lists securely - NO MORE exec()!

ignore_list, probe_ignore_list = load_ignore_lists(config)

logging.info(f"Loaded {len(ignore_list)} MAC addresses and {len(probe_ignore_list)} SSIDs")

db_path = config['paths']['kismet_logs']

try:
    list_of_files = glob.glob(db_path)
    if not list_of_files:
        raise FileNotFoundError(f"No Kismet database files found at: {db_path}")

    latest_file = max(list_of_files, key=os.path.getctime)
    logging.info(f"Using Kismet database: {latest_file}")

    # Initialize secure monitor
    secure_monitor = SecureCYTMonitor(config, ignore_list, probe_ignore_list, cyt_log, event_log)

    # Test database connection and initialize tracking lists
    with KismetDB(latest_file) as db:
        if not db.validate_connection():
            raise RuntimeError("Database validation failed")

        logger.info("Initializing secure tracking lists...")
        secure_monitor.initialize_tracking_lists(db)
        print("Initialization complete!")

except Exception as e:
    logging.error("Fatal error during initialization", exc_info=e)
    sys.exit(1)


######SECURE MAIN LOOP - All SQL injection vulnerabilities FIXED!

# Setup signal handler for graceful shutdown
def signal_handler(signum, frame):
    print("\nShutting down gracefully...")
    cyt_log.write("Shutting down gracefully...\n")
    logging.info("CYT monitoring stopped by user")
    cyt_log.close()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

# Main monitoring loop
time_count = 0
check_interval = config.get('timing', {}).get('check_interval', 60)
list_update_interval = config.get('timing', {}).get('list_update_interval', 5)

logging.info("Starting secure CYT monitoring loop...")
print(f"🔒 SECURE MODE: All SQL injection vulnerabilities have been eliminated!")
print(f"Monitoring every {check_interval} seconds, updating lists every {list_update_interval} cycles")

while True:
    time_count += 1

    try:
        # Process current activity with secure database operations
        with KismetDB(latest_file) as db:
            secure_monitor.process_current_activity(db)

            # Rotate tracking lists every N cycles (default 5 = 5 minutes)
            if time_count % list_update_interval == 0:
                logging.info(f"Rotating tracking lists (cycle {time_count})")
                secure_monitor.rotate_tracking_lists(db)

    except Exception as e:
        error_msg = f"Error in monitoring loop: {e}"
        print(error_msg)
        cyt_log.write(f"{error_msg}\n")
        logging.error(error_msg)
        continue

    # Sleep for configured interval
    time.sleep(check_interval)
