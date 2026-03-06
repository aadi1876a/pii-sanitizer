def parse_sql(filepath):

    with open(filepath, "r", encoding="utf-8") as file:
        content = file.read()

    return content