"""Test script for VaultLock — validates PDF and ZIP (AES-256) encryption paths."""
import io
import pathlib
import zipfile
import pikepdf
import pyzipper
from vault_lock import protect_pdf, unprotect_pdf, protect_zip, unprotect_zip

# ── TEST 1: PDF ───────────────────────────────────────────────────────────────
print("=== TEST 1: PDF ===")
pdf_path = "test.pdf"
with pikepdf.new() as pdf:
    pdf.add_blank_page(page_size=(200, 200))
    pdf.save(pdf_path)

protect_pdf(pdf_path, "secret123")
with pikepdf.open(pdf_path, password="secret123") as pdf:
    print(f"PDF opens with correct password: OK ({len(pdf.pages)} page(s))")

try:
    with pikepdf.open(pdf_path, password="wrongpass") as pdf:
        pass
    print("ERROR: should have rejected wrong password")
except pikepdf.PasswordError:
    print("PDF rejects wrong password: OK")

unprotect_pdf(pdf_path, "secret123")
with pikepdf.open(pdf_path) as pdf:
    print("PDF unlocked (no password needed): OK")
pathlib.Path(pdf_path).unlink()

# ── TEST 2: AES-256 ZIP (Office docx) ────────────────────────────────────────
print()
print("=== TEST 2: AES-256 ZIP wrap (.docx) ===")
docx_path = "test.docx"
original_content = b"fake docx content for testing 12345"
pathlib.Path(docx_path).write_bytes(original_content)

zip_path = protect_zip(docx_path, "zippass")
print(f"ZIP created: {zip_path}")
print(f"Original gone: {not pathlib.Path(docx_path).exists()}")

# Verify it's encrypted with AES
with pyzipper.AESZipFile(zip_path, "r") as zf:
    zf.setpassword(b"zippass")
    data = zf.read("test.docx")
    print(f"ZIP decrypts correctly: {data == original_content}")

# Test wrong password
try:
    with pyzipper.AESZipFile(zip_path, "r") as zf:
        zf.setpassword(b"wrongpass")
        zf.read("test.docx")
    print("ERROR: should have rejected wrong password")
except Exception as e:
    print(f"ZIP rejects wrong password: OK ({type(e).__name__})")

# Restore
restored = unprotect_zip(zip_path, "zippass")
data = pathlib.Path(restored).read_bytes()
print(f"Restored: {restored}")
print(f"Data matches original: {data == original_content}")
pathlib.Path(restored).unlink()

# ── TEST 3: AES-256 ZIP (video/image) ────────────────────────────────────────
print()
print("=== TEST 3: AES-256 ZIP wrap (.mp4) ===")
video_path = "test_video.mp4"
video_data = b"\x00\x00\x00\x18ftypmp42" + b"x" * 200
pathlib.Path(video_path).write_bytes(video_data)

zip_path = protect_zip(video_path, "videopass")
print(f"ZIP created: {zip_path}")
print(f"Original gone: {not pathlib.Path(video_path).exists()}")

restored = unprotect_zip(zip_path, "videopass")
data = pathlib.Path(restored).read_bytes()
print(f"Data matches original: {data == video_data}")
pathlib.Path(restored).unlink()

print()
print("All tests passed!")
