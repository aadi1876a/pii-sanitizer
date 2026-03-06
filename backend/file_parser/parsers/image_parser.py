import pytesseract
from PIL import Image
import os
import shutil

# Auto-detect tesseract — works on Windows locally AND Linux (Render)
if os.name == 'nt':  # Windows
    win_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    if os.path.exists(win_path):
        pytesseract.pytesseract.tesseract_cmd = win_path
else:  # Linux / Render
    linux_path = shutil.which("tesseract")
    if linux_path:
        pytesseract.pytesseract.tesseract_cmd = linux_path

def parse_image(file_path):
    try:
        img = Image.open(file_path)
        text = pytesseract.image_to_string(img)
        return text
    except Exception as e:
        return f"[Image parsing failed: {str(e)}]"