from pathlib import Path

p = Path("relay_list.txt")

def filter_relay(relay: str) -> bool:
    if ".onion" in relay:
        return False

    if len(relay) > 64:
        return False

    return True

values = p.read_text().splitlines()
values = [s.strip() for s in values if s.strip()]

values = [
    relay for relay in values if filter_relay(relay)
]

values = list(set(values))  # Remove duplicates
values.sort()  # Sort the values
p.write_text("\n".join(values))