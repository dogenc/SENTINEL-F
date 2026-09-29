"""
╔══════════════════════════════════════════════════════════════╗
║          PDF FORENSIC & REDACTION RECOVERY ENGINE            ║
║   Extracted & adapted from pdf_forensic_claude.py            ║
╚══════════════════════════════════════════════════════════════╝
"""
import os
import datetime
import zlib
import re
import tempfile

# ─── Dependency Detection ─────────────────────────────────────────────────────
try:
    import pikepdf
    PIKEPDF_OK = True
except ImportError:
    PIKEPDF_OK = False

try:
    from PIL import Image, ImageEnhance, ImageChops
    PIL_OK = True
except ImportError:
    PIL_OK = False

try:
    import pdf2image
    PDF2IMAGE_OK = True
except ImportError:
    PDF2IMAGE_OK = False

try:
    import pytesseract
    OCR_OK = True
except ImportError:
    OCR_OK = False

try:
    PDFINFO_OK = True
except:
    PDFINFO_OK = False

class RawPDFParser:
    """Minimal raw PDF parser for metadata extraction."""
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()

    def find_info_dict(self):
        info = {}
        pattern = rb"/(\w+)\s*\(((?:[^()\\]|\\.)*)\)"
        for m in re.finditer(pattern, self.data):
            key = m.group(1).decode("latin1","replace")
            val = m.group(2).decode("latin1","replace")
            val = val.replace("\\(","(").replace("\\)",")")
            info[key] = val
        return info

    def get_version(self):
        header = self.data[:16]
        m = re.search(rb"%PDF-(\d+\.\d+)", header)
        return m.group(1).decode() if m else "Unknown"

    def count_pages(self):
        m = re.search(rb"/Type\s*/Pages.*?/Count\s+(\d+)", self.data, re.DOTALL)
        if m:
            return int(m.group(1))
        return len(re.findall(rb"/Type\s*/Page[^s]", self.data))

    def is_encrypted(self):
        return b"/Encrypt" in self.data

    def has_javascript(self):
        return b"/JavaScript" in self.data or b"/JS" in self.data

    def count_black_rectangles(self):
        black_patterns = [
            rb"0\s+0\s+0\s+RG",
            rb"0\s+0\s+0\s+rg",
            rb"0\s+g\b",
            rb"\bBMC\b.*?/Redact",
        ]
        count = 0
        for p in black_patterns:
            count += len(re.findall(p, self.data))
        return count

    def extract_text_raw(self):
        """Extract visible strings from PDF streams."""
        texts = []
        for m in re.finditer(rb"stream\r?\n(.*?)endstream", self.data, re.DOTALL):
            raw = m.group(1)
            try:
                raw = zlib.decompress(raw)
            except:
                pass
            for sm in re.finditer(rb"\(([^)]{2,})\)", raw):
                try:
                    t = sm.group(1).decode("latin1","replace").strip()
                    if t and all(0x20 <= ord(c) < 0x7F or c in "\n\r\t" for c in t):
                        texts.append(t)
                except:
                    pass
        return "\n".join(texts)

    def find_redaction_annotations(self):
        count = len(re.findall(rb"/Subtype\s*/Redact", self.data))
        return count

    def find_embedded_images(self):
        return len(re.findall(rb"/Subtype\s*/Image", self.data))

    def find_links(self):
        return len(re.findall(rb"/Subtype\s*/Link", self.data))


# ═══════════════════════════════════════════════════════════════════════════════
#  REDACTION RECOVERY ENGINE v2.0
# ═══════════════════════════════════════════════════════════════════════════════
class RedactionRecoveryEngine:
    """
    Multi-method redaction recovery engine.
    Attempts to recover content hidden by improper PDF redactions.
    """

    def __init__(self, pdf_path, log_fn=None):
        self.pdf_path = pdf_path
        self.log = log_fn or (lambda msg, level="INFO": None)
        self.findings = []
        self.cleaned_pdf_path = None

    # ── Method 1: Remove Redaction Annotations ────────────────────────────────
    def remove_redaction_annotations(self):
        """
        Remove /Redact annotation overlays from the PDF.
        Many tools add redaction annotations WITHOUT actually removing text.
        Stripping them reveals the original content underneath.
        """
        if not PIKEPDF_OK:
            self.log("pikepdf not available – skipping annotation removal", "WARN")
            return 0

        removed = 0
        try:
            pdf = pikepdf.open(self.pdf_path)
            for page_num, page in enumerate(pdf.pages):
                if "/Annots" not in page:
                    continue
                annots = page["/Annots"]
                if not isinstance(annots, pikepdf.Array):
                    continue

                keep = []
                for annot_ref in annots:
                    try:
                        annot = annot_ref.resolve() if hasattr(annot_ref, 'resolve') else annot_ref
                        subtype = str(annot.get("/Subtype", ""))
                        if "/Redact" in subtype:
                            # Extract info about what was redacted
                            rect = annot.get("/Rect", None)
                            overlay_text = str(annot.get("/OverlayText", ""))
                            annot.get("/IC", None)
                            rect_str = ""
                            if rect:
                                try:
                                    coords = [float(x) for x in rect]
                                    rect_str = f"({coords[0]:.0f},{coords[1]:.0f})-({coords[2]:.0f},{coords[3]:.0f})"
                                except:
                                    rect_str = str(rect)

                            self.findings.append({
                                "method": "ANNOTATION REMOVAL",
                                "page": page_num + 1,
                                "type": "Redact annotation removed",
                                "rect": rect_str,
                                "overlay": overlay_text if overlay_text else None,
                                "detail": f"Redaction annotation at {rect_str} stripped"
                            })
                            removed += 1
                            self.log(f"  Removed /Redact annotation on page {page_num+1} at {rect_str}", "OK")
                            continue

                        # Also check for black square annotations used as fake redactions
                        if "/Square" in subtype or "/FreeText" in subtype:
                            ic = annot.get("/IC", None)
                            c_val = annot.get("/C", None)
                            is_black = False
                            for color_arr in [ic, c_val]:
                                if color_arr and isinstance(color_arr, pikepdf.Array):
                                    try:
                                        vals = [float(x) for x in color_arr]
                                        if all(v < 0.05 for v in vals):
                                            is_black = True
                                    except:
                                        pass
                            if is_black:
                                rect = annot.get("/Rect", None)
                                rect_str = ""
                                if rect:
                                    try:
                                        coords = [float(x) for x in rect]
                                        rect_str = f"({coords[0]:.0f},{coords[1]:.0f})-({coords[2]:.0f},{coords[3]:.0f})"
                                    except:
                                        rect_str = str(rect)
                                self.findings.append({
                                    "method": "ANNOTATION REMOVAL",
                                    "page": page_num + 1,
                                    "type": "Black overlay annotation removed",
                                    "rect": rect_str,
                                    "detail": f"Black {subtype} annotation at {rect_str} stripped"
                                })
                                removed += 1
                                self.log(f"  Removed black {subtype} on page {page_num+1} at {rect_str}", "OK")
                                continue

                        keep.append(annot_ref)

                    except Exception:
                        keep.append(annot_ref)

                if len(keep) < len(annots):
                    page["/Annots"] = pikepdf.Array(keep)

            # Save cleaned version
            if removed > 0:
                self.cleaned_pdf_path = tempfile.mktemp(suffix="_cleaned.pdf")
                pdf.save(self.cleaned_pdf_path)
                self.log(f"Cleaned PDF saved (annotations stripped): {removed} removed", "OK")
            pdf.close()

        except Exception as e:
            self.log(f"Annotation removal error: {e}", "ERR")

        return removed

    # ── Method 2: Remove Black Rectangles from Content Streams ────────────────
    def remove_black_rects_from_streams(self):
        """
        Parse PDF content streams and remove black fill+rect operations.
        Pattern: '0 g' or '0 0 0 rg' followed by 'x y w h re' + 'f' or 'F'
        This recovers text that was covered by drawn black boxes.
        """
        if not PIKEPDF_OK:
            self.log("pikepdf not available – skipping stream cleaning", "WARN")
            return 0

        removed_count = 0
        try:
            pdf = pikepdf.open(self.pdf_path)

            for page_num, page in enumerate(pdf.pages):
                if "/Contents" not in page:
                    continue

                contents = page["/Contents"]
                if isinstance(contents, pikepdf.Array):
                    content_list = list(contents)
                else:
                    content_list = [contents]


                for ci, content_ref in enumerate(content_list):
                    try:
                        obj = content_ref.resolve() if hasattr(content_ref, 'resolve') else content_ref
                        raw_bytes = bytes(obj.read_raw_bytes())
                        try:
                            stream_data = zlib.decompress(raw_bytes)
                        except:
                            stream_data = raw_bytes

                        original = stream_data
                        text = stream_data.decode("latin1", "replace")

                        # Pattern 1: "0 g ... re f" (grayscale black fill + rect + fill)
                        # Matches blocks like: 0 g\n 100 200 300 20 re\n f
                        pattern1 = re.compile(
                            r'(q\s+)?'                           # optional save state
                            r'0(?:\.0+)?\s+g\s+'                 # black fill (grayscale)
                            r'[\d.\-]+\s+[\d.\-]+\s+'            # x y
                            r'[\d.\-]+\s+[\d.\-]+\s+'            # w h
                            r're\s+'                              # rect
                            r'[fF]\*?\s*'                         # fill
                            r'(Q\s+)?',                           # optional restore state
                            re.DOTALL
                        )

                        # Pattern 2: "0 0 0 rg ... re f" (RGB black fill)
                        pattern2 = re.compile(
                            r'(q\s+)?'
                            r'0(?:\.0+)?\s+0(?:\.0+)?\s+0(?:\.0+)?\s+rg\s+'
                            r'[\d.\-]+\s+[\d.\-]+\s+'
                            r'[\d.\-]+\s+[\d.\-]+\s+'
                            r're\s+'
                            r'[fF]\*?\s*'
                            r'(Q\s+)?',
                            re.DOTALL
                        )

                        # Pattern 3: "0 0 0 RG 0 0 0 rg ... re B/f" (stroke+fill black)
                        pattern3 = re.compile(
                            r'(q\s+)?'
                            r'0(?:\.0+)?\s+0(?:\.0+)?\s+0(?:\.0+)?\s+RG\s+'
                            r'0(?:\.0+)?\s+0(?:\.0+)?\s+0(?:\.0+)?\s+rg\s+'
                            r'[\d.\-]+\s+[\d.\-]+\s+'
                            r'[\d.\-]+\s+[\d.\-]+\s+'
                            r're\s+'
                            r'[BbfF]\*?\s*'
                            r'(Q\s+)?',
                            re.DOTALL
                        )

                        # Pattern 4: "0 g" followed by multiple rects
                        pattern4 = re.compile(
                            r'0(?:\.0+)?\s+g\s+'
                            r'((?:[\d.\-]+\s+[\d.\-]+\s+[\d.\-]+\s+[\d.\-]+\s+re\s+)+)'
                            r'[fF]\*?\s*',
                            re.DOTALL
                        )

                        # Pattern 5: CMYK black (0 0 0 1 k)
                        pattern5 = re.compile(
                            r'(q\s+)?'
                            r'0(?:\.0+)?\s+0(?:\.0+)?\s+0(?:\.0+)?\s+1(?:\.0+)?\s+k\s+'
                            r'[\d.\-]+\s+[\d.\-]+\s+'
                            r'[\d.\-]+\s+[\d.\-]+\s+'
                            r're\s+'
                            r'[fF]\*?\s*'
                            r'(Q\s+)?',
                            re.DOTALL
                        )

                        for pat_name, pat in [("grayscale", pattern1),
                                               ("RGB", pattern2),
                                               ("stroke+fill", pattern3),
                                               ("multi-rect", pattern4),
                                               ("CMYK", pattern5)]:
                            matches = list(pat.finditer(text))
                            for m in reversed(matches):
                                # Extract rect dimensions for logging
                                rect_match = re.search(
                                    r'([\d.\-]+)\s+([\d.\-]+)\s+([\d.\-]+)\s+([\d.\-]+)\s+re',
                                    m.group()
                                )
                                rect_info = ""
                                if rect_match:
                                    x, y, w, h = [float(v) for v in rect_match.groups()]
                                    # Only remove if it looks like a redaction bar (wide enough)
                                    if abs(w) < 5 and abs(h) < 5:
                                        continue  # too small, probably decorative
                                    rect_info = f"x={x:.0f} y={y:.0f} w={w:.0f} h={h:.0f}"

                                # Remove the black rect from the stream
                                text = text[:m.start()] + " " + text[m.end():]
                                removed_count += 1

                                self.findings.append({
                                    "method": "STREAM CLEANING",
                                    "page": page_num + 1,
                                    "type": f"Black rect removed ({pat_name})",
                                    "rect": rect_info,
                                    "detail": f"Removed {pat_name} black rectangle: {rect_info}"
                                })
                                self.log(f"  Removed {pat_name} black rect on page {page_num+1}: {rect_info}", "OK")

                        new_data = text.encode("latin1", "replace")
                        if new_data != original:
                            try:
                                compressed = zlib.compress(new_data)
                                obj.write(compressed, filter=pikepdf.Name("/FlateDecode"))
                            except:
                                obj.write(new_data)

                    except Exception as e:
                        self.log(f"  Stream parse error page {page_num+1}: {e}", "WARN")

            if removed_count > 0:
                self.cleaned_pdf_path = tempfile.mktemp(suffix="_cleaned.pdf")
                pdf.save(self.cleaned_pdf_path)
                self.log(f"Stream-cleaned PDF saved: {removed_count} black rects removed", "OK")
            pdf.close()

        except Exception as e:
            self.log(f"Stream cleaning error: {e}", "ERR")

        return removed_count

    # ── Method 3: Extract Text Under Redacted Areas ───────────────────────────
    def extract_text_under_redactions(self):
        """
        Even after redaction annotations, the text operators (BT...ET blocks)
        often remain in the content stream. This method extracts ALL text
        from content streams, including text positioned under redaction areas.
        """
        if not PIKEPDF_OK:
            return []

        recovered_texts = []
        try:
            pdf = pikepdf.open(self.pdf_path)
            for page_num, page in enumerate(pdf.pages):
                # Collect redaction rects
                redact_rects = []
                if "/Annots" in page:
                    annots = page["/Annots"]
                    if isinstance(annots, pikepdf.Array):
                        for annot_ref in annots:
                            try:
                                annot = annot_ref.resolve() if hasattr(annot_ref, 'resolve') else annot_ref
                                subtype = str(annot.get("/Subtype", ""))
                                if "/Redact" in subtype or "/Square" in subtype:
                                    rect = annot.get("/Rect", None)
                                    if rect:
                                        coords = [float(x) for x in rect]
                                        redact_rects.append(coords)
                            except:
                                pass

                # Extract all text blocks with positions
                if "/Contents" not in page:
                    continue

                contents = page["/Contents"]
                if isinstance(contents, pikepdf.Array):
                    content_list = list(contents)
                else:
                    content_list = [contents]

                all_text_blocks = []
                for content_ref in content_list:
                    try:
                        obj = content_ref.resolve() if hasattr(content_ref, 'resolve') else content_ref
                        raw_bytes = bytes(obj.read_raw_bytes())
                        try:
                            stream_data = zlib.decompress(raw_bytes)
                        except:
                            stream_data = raw_bytes

                        text = stream_data.decode("latin1", "replace")

                        # Extract BT...ET blocks with text and position
                        bt_blocks = re.finditer(r'BT(.*?)ET', text, re.DOTALL)
                        for bt in bt_blocks:
                            block = bt.group(1)

                            # Extract position (Td, TD, Tm operators)
                            positions = re.findall(
                                r'([\d.\-]+)\s+([\d.\-]+)\s+(?:Td|TD|Tm)', block
                            )
                            pos = None
                            if positions:
                                try:
                                    pos = (float(positions[-1][0]), float(positions[-1][1]))
                                except:
                                    pass

                            # Extract text strings
                            strings = re.findall(r'\(([^)]*)\)', block)
                            # Also handle hex strings
                            hex_strings = re.findall(r'<([0-9a-fA-F]+)>', block)
                            for hs in hex_strings:
                                try:
                                    decoded = bytes.fromhex(hs).decode("latin1", "replace")
                                    strings.append(decoded)
                                except:
                                    pass

                            joined = " ".join(s for s in strings if len(s.strip()) > 0)
                            if joined.strip():
                                all_text_blocks.append({
                                    "text": joined.strip(),
                                    "pos": pos,
                                    "page": page_num + 1
                                })

                    except:
                        pass

                # Check which text blocks fall within redaction areas
                for tb in all_text_blocks:
                    is_under_redaction = False
                    if tb["pos"] and redact_rects:
                        tx, ty = tb["pos"]
                        for rect in redact_rects:
                            x1, y1, x2, y2 = rect
                            # Normalize
                            rx_min, rx_max = min(x1, x2), max(x1, x2)
                            ry_min, ry_max = min(y1, y2), max(y1, y2)
                            if rx_min <= tx <= rx_max and ry_min <= ty <= ry_max:
                                is_under_redaction = True
                                break

                    if is_under_redaction:
                        recovered_texts.append({
                            "page": tb["page"],
                            "text": tb["text"],
                            "pos": tb["pos"],
                            "source": "UNDER_REDACTION"
                        })
                        self.findings.append({
                            "method": "TEXT UNDER REDACTION",
                            "page": tb["page"],
                            "type": "Hidden text recovered",
                            "rect": f"pos=({tb['pos'][0]:.0f},{tb['pos'][1]:.0f})" if tb["pos"] else "",
                            "detail": tb["text"][:100]
                        })
                    else:
                        recovered_texts.append({
                            "page": tb["page"],
                            "text": tb["text"],
                            "pos": tb["pos"],
                            "source": "VISIBLE"
                        })

            pdf.close()
        except Exception as e:
            self.log(f"Text extraction error: {e}", "ERR")

        return recovered_texts

    # ── Method 4: Visual Diff — Compare original vs cleaned ───────────────────
    def visual_diff_recovery(self):
        """
        Render the original and cleaned PDF, then diff the images.
        Areas that changed (redaction removed) are highlighted.
        Returns list of page images (original, cleaned, diff).
        """
        if not PDF2IMAGE_OK or not PIL_OK:
            self.log("pdf2image/Pillow needed for visual diff", "WARN")
            return []

        if not self.cleaned_pdf_path or not os.path.exists(self.cleaned_pdf_path):
            return []

        diffs = []
        try:
            orig_imgs = pdf2image.convert_from_path(self.pdf_path, dpi=150)
            clean_imgs = pdf2image.convert_from_path(self.cleaned_pdf_path, dpi=150)

            for i, (orig, clean) in enumerate(zip(orig_imgs, clean_imgs)):
                # Ensure same size
                if orig.size != clean.size:
                    clean = clean.resize(orig.size, Image.LANCZOS)

                # Compute diff
                diff = ImageChops.difference(orig, clean)

                # Enhance diff for visibility
                enhancer = ImageEnhance.Contrast(diff)
                diff_enhanced = enhancer.enhance(5.0)

                # Create composite: highlight changed areas in red
                composite = orig.copy().convert("RGBA")
                diff_gray = diff.convert("L")

                # Threshold
                threshold = 30
                mask = diff_gray.point(lambda p: 255 if p > threshold else 0)

                # Red overlay
                red_overlay = Image.new("RGBA", orig.size, (255, 0, 0, 0))
                red_fill = Image.new("RGBA", orig.size, (255, 60, 60, 120))
                red_overlay = Image.composite(red_fill, red_overlay, mask)
                composite = Image.alpha_composite(composite, red_overlay)

                has_changes = any(mask.getdata())

                diffs.append({
                    "page": i + 1,
                    "original": orig,
                    "cleaned": clean,
                    "diff": diff_enhanced,
                    "composite": composite.convert("RGB"),
                    "has_changes": has_changes
                })

                if has_changes:
                    self.findings.append({
                        "method": "VISUAL DIFF",
                        "page": i + 1,
                        "type": "Visual difference detected",
                        "rect": "",
                        "detail": "Page content changed after redaction removal"
                    })

        except Exception as e:
            self.log(f"Visual diff error: {e}", "ERR")

        return diffs

    # ── Method 5: OCR on Cleaned PDF ──────────────────────────────────────────
    def ocr_cleaned_pages(self):
        """
        Run OCR on the cleaned (redaction-stripped) PDF to recover
        text that was visually hidden.
        """
        if not PDF2IMAGE_OK or not OCR_OK:
            self.log("pdf2image + tesseract needed for OCR recovery", "WARN")
            return []

        target = self.cleaned_pdf_path or self.pdf_path
        ocr_results = []
        try:
            imgs = pdf2image.convert_from_path(target, dpi=200)
            for i, img in enumerate(imgs):
                try:
                    # Also try with image processing to recover faint text
                    # Grayscale + contrast boost
                    gray = img.convert("L")
                    enhancer = ImageEnhance.Contrast(gray)
                    enhanced = enhancer.enhance(2.0)

                    # Standard OCR
                    text_normal = pytesseract.image_to_string(img, lang="deu+eng")
                    # Enhanced OCR
                    text_enhanced = pytesseract.image_to_string(enhanced, lang="deu+eng")

                    # Combine (deduplicated)
                    combined = text_normal
                    if len(text_enhanced) > len(text_normal):
                        combined = text_enhanced

                    if combined.strip():
                        ocr_results.append({
                            "page": i + 1,
                            "text": combined.strip(),
                            "source": "OCR_CLEANED" if target != self.pdf_path else "OCR_ORIGINAL"
                        })
                except Exception as e:
                    self.log(f"OCR page {i+1}: {e}", "WARN")

        except Exception as e:
            self.log(f"OCR error: {e}", "ERR")

        return ocr_results

    # ── Method 6: Extract All Embedded Content ────────────────────────────────
    def extract_hidden_layers(self):
        """
        Look for Optional Content Groups (layers) that may be hidden,
        and extract text from them. Some redactions use OCG to hide content.
        """
        if not PIKEPDF_OK:
            return []

        hidden_content = []
        try:
            pdf = pikepdf.open(self.pdf_path)

            # Check for Optional Content (OCG layers)
            root = pdf.Root
            if "/OCProperties" in root:
                oc_props = root["/OCProperties"]
                if "/OCGs" in oc_props:
                    ocgs = oc_props["/OCGs"]
                    for ocg_ref in ocgs:
                        try:
                            ocg = ocg_ref.resolve() if hasattr(ocg_ref, 'resolve') else ocg_ref
                            name = str(ocg.get("/Name", "unnamed"))
                            hidden_content.append({
                                "type": "OCG Layer",
                                "name": name,
                                "detail": f"Optional Content Group: {name}"
                            })
                            self.findings.append({
                                "method": "HIDDEN LAYERS",
                                "page": 0,
                                "type": f"OCG Layer: {name}",
                                "rect": "",
                                "detail": f"Hidden layer detected: {name}"
                            })
                        except:
                            pass

            # Check for form fields that might contain hidden data
            if "/AcroForm" in root:
                try:
                    acroform = root["/AcroForm"]
                    if "/Fields" in acroform:
                        fields = acroform["/Fields"]
                        for field_ref in fields:
                            try:
                                field = field_ref.resolve() if hasattr(field_ref, 'resolve') else field_ref
                                fname = str(field.get("/T", ""))
                                fval = str(field.get("/V", ""))
                                if fval and fval != "None":
                                    hidden_content.append({
                                        "type": "Form Field",
                                        "name": fname,
                                        "value": fval,
                                        "detail": f"Field '{fname}' = '{fval}'"
                                    })
                                    self.findings.append({
                                        "method": "HIDDEN LAYERS",
                                        "page": 0,
                                        "type": f"Form field: {fname}",
                                        "rect": "",
                                        "detail": f"Value: {fval[:100]}"
                                    })
                            except:
                                pass
                except:
                    pass

            pdf.close()
        except Exception as e:
            self.log(f"Hidden layer scan error: {e}", "ERR")

        return hidden_content

    # ── Master Recovery Pipeline ──────────────────────────────────────────────
    def run_full_recovery(self, progress_fn=None):
        """
        Execute all recovery methods in sequence.
        Returns a comprehensive report dict.
        """
        report = {
            "file": self.pdf_path,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "methods": {},
            "total_findings": 0,
            "recovered_texts": [],
            "visual_diffs": [],
        }

        # Step 1: Remove annotations
        if progress_fn:
            progress_fn("Method 1/6: Removing redaction annotations...", 5)
        annot_count = self.remove_redaction_annotations()
        report["methods"]["annotation_removal"] = {
            "removed": annot_count,
            "status": "OK" if annot_count > 0 else "CLEAN"
        }

        # Step 2: Remove black rects from streams
        if progress_fn:
            progress_fn("Method 2/6: Cleaning content streams...", 20)
        rect_count = self.remove_black_rects_from_streams()
        report["methods"]["stream_cleaning"] = {
            "removed": rect_count,
            "status": "OK" if rect_count > 0 else "CLEAN"
        }

        # Step 3: Extract text under redactions
        if progress_fn:
            progress_fn("Method 3/6: Extracting text under redactions...", 35)
        texts = self.extract_text_under_redactions()
        under_redaction = [t for t in texts if t["source"] == "UNDER_REDACTION"]
        report["methods"]["text_under_redaction"] = {
            "found": len(under_redaction),
            "texts": under_redaction,
            "status": "OK" if under_redaction else "CLEAN"
        }
        report["recovered_texts"].extend(under_redaction)

        # Step 4: Hidden layers
        if progress_fn:
            progress_fn("Method 4/6: Scanning hidden layers...", 50)
        hidden = self.extract_hidden_layers()
        report["methods"]["hidden_layers"] = {
            "found": len(hidden),
            "items": hidden,
            "status": "OK" if hidden else "CLEAN"
        }

        # Step 5: Visual diff
        if progress_fn:
            progress_fn("Method 5/6: Visual diff analysis...", 65)
        diffs = self.visual_diff_recovery()
        changed_pages = [d for d in diffs if d["has_changes"]]
        report["methods"]["visual_diff"] = {
            "pages_changed": len(changed_pages),
            "status": "OK" if changed_pages else "CLEAN"
        }
        report["visual_diffs"] = diffs

        # Step 6: OCR
        if progress_fn:
            progress_fn("Method 6/6: OCR text recovery...", 80)
        ocr_texts = self.ocr_cleaned_pages()
        report["methods"]["ocr_recovery"] = {
            "pages": len(ocr_texts),
            "texts": ocr_texts,
            "status": "OK" if ocr_texts else "CLEAN"
        }
        report["recovered_texts"].extend(ocr_texts)

        report["total_findings"] = len(self.findings)

        # Cleanup temp files
        # (keep cleaned_pdf_path for save feature)

        if progress_fn:
            progress_fn("Recovery complete", 100)

        return report

    def get_cleaned_pdf_path(self):
        return self.cleaned_pdf_path

    def cleanup(self):
        if self.cleaned_pdf_path and os.path.exists(self.cleaned_pdf_path):
            try:
                os.unlink(self.cleaned_pdf_path)
            except:
                pass


# ─── Splash Screen ────────────────────────────────────────────────────────────
