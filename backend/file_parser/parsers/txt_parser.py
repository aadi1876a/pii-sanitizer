def parse_txt(filepath):

    with open(filepath, "r", encoding="utf-8") as file:
        text = file.read()

    return text