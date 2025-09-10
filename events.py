import json
from datetime import datetime
from json import JSONEncoder, JSONDecoder
from typing import Dict, Any, IO


class Event:
    timestamp: datetime

    def __init__(self, timestamp: datetime):
        super().__init__()
        self.timestamp = timestamp


class SSIDProbeEvent(Event):
    ssid: str
    mac: str

    def __init__(self,timestamp: datetime, ssid: str, mac: str):
        super().__init__(timestamp)
        self.ssid = ssid
        self.mac = mac


class EventEncoder(JSONEncoder):
    def default(self, o):
        if isinstance(o, Event):
            return EventEncoder.encode_event(o)
        else:
            return super().default(o)

    @staticmethod
    def encode_event(event: Event) -> Dict:
        data = {}

        if isinstance(event, SSIDProbeEvent):
            data['type'] = 'ssid-probe'
            data['ssid'] = event.ssid
        else:
            raise TypeError(f'Can only serialize known subclasses of Event, not {event.__class__.__name__}.')

        data['timestamp'] = event.timestamp.strftime('%m/%d/%Y %H-%M-%S')

        return data


def encode_event(event: Any) -> Dict[str, Any]:
    if not isinstance(event, Event):
        raise TypeError(f'Can only serialize subclasses of Event, not {event.__class__.__name__}.')

    data = {}

    if isinstance(event, SSIDProbeEvent):
        data['type'] = 'ssid-probe'
        data['ssid'] = event.ssid
        data['mac'] = event.mac
    else:
        raise TypeError(f'Can only serialize known subclasses of Event, not {event.__class__.__name__}.')

    data['timestamp'] = event.timestamp.strftime('%m/%d/%Y %H:%M:%S')

    return data


def decode_event(data: Dict[str, Any]):
    if not 'type' in data:
        return data

    event_type = data['type']
    timestamp = datetime.strptime(data['timestamp'], '%m/%d/%Y %H:%M:%S')

    if event_type == 'ssid-probe':
        return SSIDProbeEvent(timestamp, data['ssid'], data['mac'])
    else:
        raise TypeError(f'Unknown event type "{event_type}" for data {data}')


def write_event_log(file: IO, event: Event):
    # the type for fp is correct, intellij is just confused
    # noinspection PyTypeChecker
    json.dump(event, fp=file, default=encode_event, indent=0)
    file.write('\n')


def read_event_line(line: str) -> Event:
    return json.loads(line, object_hook=decode_event)
