from docx import Document

def parse_docx(filepath):

    doc = Document(filepath)

    text = ""

    for para in doc.paragraphs:
        text += para.text + "\n"

    return text