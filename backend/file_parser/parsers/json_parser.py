import json

def parse_json(filepath):

    with open(filepath, "r", encoding="utf-8") as file:
        data = json.load(file)

    text = json.dumps(data, indent=2)

    return text