# ============================================================
# ABACUS SECURITY AGENT
# Custom Endpoint Telemetry Agent
#
# Version: 0.4.0
#
# Responsibilities:
#   1. Collect endpoint telemetry
#   2. Package telemetry
#   3. Send telemetry to Security Console
#   4. Retry failed requests
#   5. Queue telemetry if server is unavailable
#
# The agent does NOT perform final security decisions.
# Detection and risk scoring happen centrally.
# ============================================================

import platform
import socket
import getpass
import time
import uuid
import psutil
import requests
import json
import os
import sys
import logging
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, List


# ============================================================
# CONFIGURATION
# ============================================================

AGENT_VERSION = "0.4.0"

SERVER_URL = os.getenv(
    "ABACUS_SERVER",
    "http://127.0.0.1:8000"
)

LOG_DIR = "logs"

os.makedirs(LOG_DIR, exist_ok=True)


# ============================================================
# PERSISTENT DEVICE ID
# ============================================================

DEVICE_ID_FILE = os.path.join(
    LOG_DIR,
    "device_id.txt"
)


def get_device_id() -> str:
    """
    Get a persistent device ID.

    We do NOT want a new device identity every time
    the agent starts.

    Otherwise the central server would think:

        Run 1 -> Device A
        Run 2 -> Device B
        Run 3 -> Device C

    even though it is the same physical machine.
    """

    try:

        if os.path.exists(DEVICE_ID_FILE):

            with open(
                DEVICE_ID_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                device_id = file.read().strip()

                if device_id:
                    return device_id

        device_id = str(uuid.uuid4())

        with open(
            DEVICE_ID_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(device_id)

        return device_id

    except Exception:

        # Fallback if the ID file cannot be created.
        return str(uuid.uuid4())


DEVICE_ID = get_device_id()


# ============================================================
# LOGGING
# ============================================================

log_file = os.path.join(
    LOG_DIR,
    f"agent_{datetime.now().strftime('%Y%m%d')}.log"
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(
            log_file,
            encoding="utf-8"
        ),
        logging.StreamHandler(sys.stdout)
    ]
)


logger = logging.getLogger(
    "AbacusAgent"
)


# ============================================================
# TIME
# ============================================================

def utc_timestamp() -> str:
    """
    Return a standardized UTC timestamp.
    """

    return datetime.now(
        timezone.utc
    ).isoformat()


# ============================================================
# LOCAL IP
# ============================================================

def get_local_ip() -> str:

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        sock.connect(
            ("8.8.8.8", 80)
        )

        ip = sock.getsockname()[0]

        sock.close()

        return ip

    except Exception:

        return "unknown"


# ============================================================
# DEVICE INFORMATION
# ============================================================

def collect_device_info() -> Dict[str, Any]:

    return {

        "device_id": DEVICE_ID,

        "hostname": socket.gethostname(),

        "username": getpass.getuser(),

        "os": platform.system(),

        "os_version": platform.version(),

        "platform_release": platform.release(),

        "machine": platform.machine(),

        "processor": platform.processor(),

        "local_ip": get_local_ip(),

        "agent_version": AGENT_VERSION,

        "timestamp": utc_timestamp()
    }


# ============================================================
# SYSTEM INFORMATION
# ============================================================

def collect_system_info() -> Dict[str, Any]:

    try:

        memory = psutil.virtual_memory()

        # Windows drive.
        if platform.system() == "Windows":

            disk_path = os.environ.get(
                "SystemDrive",
                "C:"
            ) + "\\"

        else:

            disk_path = "/"

        disk = psutil.disk_usage(
            disk_path
        )

        cpu_freq = psutil.cpu_freq()

        return {

            "cpu": {

                "percent": psutil.cpu_percent(
                    interval=1
                ),

                "cores": psutil.cpu_count(),

                "freq": (
                    cpu_freq._asdict()
                    if cpu_freq
                    else None
                )
            },

            "memory": {

                "total": memory.total,

                "available": memory.available,

                "percent": memory.percent,

                "used": memory.used,

                "free": memory.free
            },

            "disk": {

                "total": disk.total,

                "used": disk.used,

                "free": disk.free,

                "percent": disk.percent
            },

            "boot_time": datetime.fromtimestamp(
                psutil.boot_time()
            ).isoformat(),

            "process_count": len(
                psutil.pids()
            ),

            "timestamp": utc_timestamp()
        }

    except Exception as e:

        logger.error(
            "System collection failed: %s",
            e
        )

        return {
            "error": str(e),
            "timestamp": utc_timestamp()
        }


# ============================================================
# NETWORK CONNECTIONS
# ============================================================

def collect_network_connections() -> Dict[str, Any]:

    connections: List[Dict[str, Any]] = []

    try:

        network_connections = psutil.net_connections(
            kind="inet"
        )

        for connection in network_connections:

            try:

                local_address = connection.laddr
                remote_address = connection.raddr

                local_ip = (
                    local_address.ip
                    if local_address
                    else None
                )

                local_port = (
                    local_address.port
                    if local_address
                    else None
                )

                remote_ip = (
                    remote_address.ip
                    if remote_address
                    else None
                )

                remote_port = (
                    remote_address.port
                    if remote_address
                    else None
                )

                process_name = "unknown"

                process_exe = None

                if connection.pid:

                    try:

                        process = psutil.Process(
                            connection.pid
                        )

                        process_name = process.name()

                        try:

                            process_exe = process.exe()

                        except (
                            psutil.AccessDenied,
                            psutil.NoSuchProcess
                        ):

                            process_exe = None

                    except (
                        psutil.NoSuchProcess,
                        psutil.AccessDenied
                    ):

                        process_name = "unknown"

                connections.append(
                    {

                        "pid": connection.pid,

                        "process": process_name,

                        "process_exe": process_exe,

                        "family": str(
                            connection.family
                        ),

                        "type": str(
                            connection.type
                        ),

                        "local_ip": local_ip,

                        "local_port": local_port,

                        "remote_ip": remote_ip,

                        "remote_port": remote_port,

                        "status": connection.status
                    }
                )

            except Exception as e:

                logger.debug(
                    "Failed to process connection: %s",
                    e
                )

                continue

    except psutil.AccessDenied:

        logger.warning(
            "Network connection access denied."
        )

    except Exception as e:

        logger.error(
            "Network collection failed: %s",
            e
        )

    return {

        "connection_count": len(
            connections
        ),

        "connections": connections,

        "timestamp": utc_timestamp()
    }


# ============================================================
# PROCESS INFORMATION
# ============================================================

def collect_process_info() -> Dict[str, Any]:

    processes = []

    try:

        for process in psutil.process_iter(
            [
                "pid",
                "name",
                "cpu_percent",
                "memory_percent",
                "create_time",
                "status",
                "username",
                "exe"
            ]
        ):

            try:

                info = process.info.copy()

                create_time = info.get(
                    "create_time"
                )

                if create_time:

                    info["create_time"] = (
                        datetime.fromtimestamp(
                            create_time
                        ).isoformat()
                    )

                processes.append(
                    info
                )

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied
            ):

                continue

            except Exception:

                continue

        # Highest CPU processes first.
        processes.sort(
            key=lambda item: (
                item.get(
                    "cpu_percent"
                ) or 0
            ),
            reverse=True
        )

        return {

            "total_processes": len(
                processes
            ),

            # Don't dump hundreds of processes
            # every telemetry cycle.
            "top_processes": processes[:20],

            "timestamp": utc_timestamp()
        }

    except Exception as e:

        logger.error(
            "Process collection failed: %s",
            e
        )

        return {
            "error": str(e),
            "total_processes": 0,
            "top_processes": [],
            "timestamp": utc_timestamp()
        }


# ============================================================
# TELEMETRY SENDER
# ============================================================

class TelemetrySender:

    def __init__(
        self,
        server_url: str,
        device_id: str,
        max_retries: int = 3
    ):

        self.server_url = server_url.rstrip(
            "/"
        )

        self.device_id = device_id

        self.max_retries = max_retries

        self.session = requests.Session()

        self.session.headers.update(
            {
                "Content-Type": "application/json",

                "User-Agent": (
                    f"AbacusAgent/{AGENT_VERSION}"
                )
            }
        )


    # --------------------------------------------------------
    # EVENT ID
    # --------------------------------------------------------

    def generate_event_id(
        self,
        telemetry_type: str
    ) -> str:

        return str(
            uuid.uuid4()
        )


    # --------------------------------------------------------
    # SEND TELEMETRY
    # --------------------------------------------------------

    def send_telemetry(
        self,
        telemetry_type: str,
        payload: Dict[str, Any]
    ) -> bool:

        event_id = self.generate_event_id(
            telemetry_type
        )

        data = {

            "event_id": event_id,

            "device_id": self.device_id,

            "timestamp": utc_timestamp(),

            "telemetry_type": telemetry_type,

            "payload": payload,

            "agent_version": AGENT_VERSION
        }

        for attempt in range(
            1,
            self.max_retries + 1
        ):

            try:

                response = self.session.post(

                    f"{self.server_url}/api/telemetry",

                    json=data,

                    timeout=5
                )

                if response.status_code == 200:

                    logger.info(
                        "[+] Telemetry sent: %s",
                        telemetry_type
                    )

                    return True

                logger.warning(
                    "Server returned HTTP %s: %s",
                    response.status_code,
                    response.text
                )

            except requests.exceptions.ConnectionError:

                logger.warning(
                    "Cannot connect to security server "
                    "(attempt %s/%s)",
                    attempt,
                    self.max_retries
                )

            except requests.exceptions.Timeout:

                logger.warning(
                    "Telemetry request timed out "
                    "(attempt %s/%s)",
                    attempt,
                    self.max_retries
                )

            except Exception as e:

                logger.warning(
                    "Telemetry error: %s",
                    e
                )

            if attempt < self.max_retries:

                time.sleep(
                    2 ** (attempt - 1)
                )

        # All attempts failed.
        self.queue_telemetry(
            data
        )

        logger.warning(
            "[!] Queued telemetry for later: %s",
            telemetry_type
        )

        return False


    # --------------------------------------------------------
    # OFFLINE QUEUE
    # --------------------------------------------------------

    def queue_telemetry(
        self,
        data: Dict[str, Any]
    ):

        queue_file = os.path.join(
            LOG_DIR,
            "offline_queue.json"
        )

        try:

            if os.path.exists(
                queue_file
            ):

                with open(
                    queue_file,
                    "r",
                    encoding="utf-8"
                ) as file:

                    queue = json.load(
                        file
                    )

            else:

                queue = []

            queue.append(
                data
            )

            # Prevent unlimited growth.
            queue = queue[-1000:]

            with open(
                queue_file,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    queue,
                    file,
                    indent=2
                )

        except Exception as e:

            logger.error(
                "Could not queue telemetry: %s",
                e
            )


    # --------------------------------------------------------
    # RETRY OFFLINE QUEUE
    # --------------------------------------------------------

    def send_queued_telemetry(self) -> int:

        queue_file = os.path.join(
            LOG_DIR,
            "offline_queue.json"
        )

        if not os.path.exists(
            queue_file
        ):

            return 0

        try:

            with open(
                queue_file,
                "r",
                encoding="utf-8"
            ) as file:

                queue = json.load(
                    file
                )

            if not queue:

                return 0

            remaining = []

            sent_count = 0

            for item in queue:

                try:

                    response = self.session.post(

                        f"{self.server_url}/api/telemetry",

                        json=item,

                        timeout=5
                    )

                    if response.status_code == 200:

                        sent_count += 1

                    else:

                        remaining.append(
                            item
                        )

                except Exception:

                    remaining.append(
                        item
                    )

            with open(
                queue_file,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    remaining,
                    file,
                    indent=2
                )

            return sent_count

        except Exception as e:

            logger.error(
                "Queue processing failed: %s",
                e
            )

            return 0


# ============================================================
# ABACUS AGENT
# ============================================================

class AbacusAgent:

    def __init__(
        self,
        server_url: str
    ):

        self.server_url = server_url

        self.sender = TelemetrySender(
            server_url=server_url,
            device_id=DEVICE_ID
        )


    # --------------------------------------------------------
    # COLLECTION CYCLE
    # --------------------------------------------------------

    def run_once(self):

        logger.info(
            "=" * 70
        )

        logger.info(
            "STARTING TELEMETRY COLLECTION"
        )

        logger.info(
            "=" * 70
        )

        results = {}

        # ----------------------------------------------------
        # DEVICE
        # ----------------------------------------------------

        logger.info(
            "Collecting device information..."
        )

        device = collect_device_info()

        results["device"] = (
            self.sender.send_telemetry(
                "device",
                device
            )
        )

        # ----------------------------------------------------
        # SYSTEM
        # ----------------------------------------------------

        logger.info(
            "Collecting system information..."
        )

        system = collect_system_info()

        results["system"] = (
            self.sender.send_telemetry(
                "system",
                system
            )
        )

        # ----------------------------------------------------
        # NETWORK
        # ----------------------------------------------------

        logger.info(
            "Collecting network information..."
        )

        network = collect_network_connections()

        results["network"] = (
            self.sender.send_telemetry(
                "network",
                network
            )
        )

        # ----------------------------------------------------
        # PROCESSES
        # ----------------------------------------------------

        logger.info(
            "Collecting process information..."
        )

        processes = collect_process_info()

        results["processes"] = (
            self.sender.send_telemetry(
                "processes",
                processes
            )
        )

        # ----------------------------------------------------
        # OFFLINE QUEUE
        # ----------------------------------------------------

        queued = (
            self.sender.send_queued_telemetry()
        )

        if queued:

            logger.info(
                "[+] Sent %s queued telemetry items",
                queued
            )

        # ----------------------------------------------------
        # RESULT
        # ----------------------------------------------------

        success_count = sum(
            1
            for value in results.values()
            if value
        )

        total_count = len(
            results
        )

        logger.info(
            "=" * 70
        )

        logger.info(
            "[COMPLETE] Sent %s/%s telemetry types",
            success_count,
            total_count
        )

        logger.info(
            "=" * 70
        )

        return results


    # --------------------------------------------------------
    # CONTINUOUS MODE
    # --------------------------------------------------------

    def run_continuous(
        self,
        interval: int = 30
    ):

        logger.info(
            "Continuous mode enabled. "
            "Interval: %s seconds",
            interval
        )

        try:

            while True:

                self.run_once()

                time.sleep(
                    interval
                )

        except KeyboardInterrupt:

            logger.info(
                "Agent stopped by user."
            )


# ============================================================
# COMMAND LINE
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Abacus Security Agent"
        )
    )

    parser.add_argument(
        "--once",
        "-o",
        action="store_true",
        help="Run one telemetry collection cycle"
    )

    parser.add_argument(
        "--continuous",
        "-c",
        action="store_true",
        help="Continuously collect telemetry"
    )

    parser.add_argument(
        "--interval",
        "-i",
        type=int,
        default=30,
        help="Collection interval in seconds"
    )

    parser.add_argument(
        "--server",
        "-s",
        type=str,
        default=SERVER_URL,
        help="Security Console URL"
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging"
    )

    args = parser.parse_args()

    if args.verbose:

        logging.getLogger().setLevel(
            logging.DEBUG
        )

    logger.info(
        "=" * 70
    )

    logger.info(
        "ABACUS SECURITY AGENT"
    )

    logger.info(
        "Version: %s",
        AGENT_VERSION
    )

    logger.info(
        "Device ID: %s",
        DEVICE_ID
    )

    logger.info(
        "Security Console: %s",
        args.server
    )

    logger.info(
        "=" * 70
    )

    agent = AbacusAgent(
        server_url=args.server
    )

    if args.continuous:

        agent.run_continuous(
            interval=args.interval
        )

    else:

        # --once and default mode both perform one cycle.
        agent.run_once()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()