import pandas as pd

def parse_csv(filepath):

    df = pd.read_csv(filepath)

    text = df.to_string()

    return text