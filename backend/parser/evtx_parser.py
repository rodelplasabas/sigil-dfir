from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

NAMESPACE = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}


def parse_evtx(file_path, max_records=0):
    events = []

    with Evtx(file_path) as log:
        for i, record in enumerate(log.records()):
            if max_records > 0 and i >= max_records:
                break

            try:
                xml = record.xml()
                root = ET.fromstring(xml)

                system = root.find("ns:System", NAMESPACE)

                event_id = None
                timestamp = None
                provider = None
                computer = None
                channel = None
                record_id = None

                if system is not None:
                    event_id_elem = system.find("ns:EventID", NAMESPACE)
                    time_elem = system.find("ns:TimeCreated", NAMESPACE)
                    provider_elem = system.find("ns:Provider", NAMESPACE)
                    computer_elem = system.find("ns:Computer", NAMESPACE)
                    channel_elem = system.find("ns:Channel", NAMESPACE)
                    record_id_elem = system.find("ns:EventRecordID", NAMESPACE)

                    if event_id_elem is not None:
                        event_id = event_id_elem.text

                    if time_elem is not None:
                        timestamp = time_elem.attrib.get("SystemTime")

                    if provider_elem is not None:
                        provider = provider_elem.attrib.get("Name")

                    if computer_elem is not None:
                        computer = computer_elem.text

                    if channel_elem is not None:
                        channel = channel_elem.text

                    if record_id_elem is not None:
                        record_id = record_id_elem.text

                # Extract EventData fields
                message = ""
                event_data_fields = {}

                eventdata = root.find("ns:EventData", NAMESPACE)
                if eventdata is not None:
                    for data in eventdata:
                        name = data.attrib.get("Name", "")
                        value = data.text or ""
                        if name:
                            event_data_fields[name] = value
                        if value:
                            message += f"{value} "

                # Also check UserData
                userdata = root.find("ns:UserData", NAMESPACE)
                if userdata is not None:
                    for elem in userdata.iter():
                        if elem.text and elem.text.strip():
                            message += f"{elem.text.strip()} "

                events.append({
                    "timestamp": timestamp,
                    "event_id": event_id,
                    "provider": provider,
                    "computer": computer,
                    "channel": channel,
                    "record_id": record_id,
                    "message": message.strip(),
                    "fields": event_data_fields
                })

            except Exception:
                continue

    return events