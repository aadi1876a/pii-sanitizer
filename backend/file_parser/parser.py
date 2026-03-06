from file_parser.parsers.txt_parser import parse_txt
from file_parser.parsers.csv_parser import parse_csv
from file_parser.parsers.json_parser import parse_json
from file_parser.parsers.docx_parser import parse_docx
from file_parser.parsers.pdf_parser import parse_pdf
from file_parser.parsers.sql_parser import parse_sql
from file_parser.parsers.image_parser import parse_image
from detector.detector import PIIDetector
from sanitizer.sanitizer import FileSanitizer


def parse_file(filepath):

    filepath_lower = filepath.lower()

    if filepath_lower.endswith(".pdf"):
        return parse_pdf(filepath)

    elif filepath_lower.endswith(".docx"):
        return parse_docx(filepath)

    elif filepath_lower.endswith(".sql"):
        return parse_sql(filepath)

    elif filepath_lower.endswith(".csv"):
        return parse_csv(filepath)

    elif filepath_lower.endswith(".json"):
        return parse_json(filepath)

    elif filepath_lower.endswith(".txt"):
        return parse_txt(filepath)

    elif filepath_lower.endswith(".png") or filepath_lower.endswith(".jpg") or filepath_lower.endswith(".jpeg"):
        return parse_image(filepath)

    else:
        return "Unsupported file format"