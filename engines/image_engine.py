"""
╔══════════════════════════════════════════════════════════════╗
║          IMAGE FORENSIC ENGINE                               ║
║   Extracted & adapted from DGKN picture_forensics_suite.py   ║
╚══════════════════════════════════════════════════════════════╝
"""
import io
import datetime
import re
from pathlib import Path

# ─── Dependency Detection ─────────────────────────────────────────────────────
try:
    from PIL import Image, ImageEnhance, ImageFilter, ImageDraw
    from PIL import ImageChops, ImageOps
    PIL_OK = True
except ImportError:
    PIL_OK = False

try:
    import numpy as np
    NUMPY_OK = True
except ImportError:
    NUMPY_OK = False

try:
    import piexif
    PIEXIF_OK = True
except ImportError:
    PIEXIF_OK = False

try:
    from PIL.ExifTags import TAGS as EXIF_TAGS, GPSTAGS
    EXIFTAGS_OK = True
except ImportError:
    EXIFTAGS_OK = False

try:
    import scipy  # noqa: F401 – nur Verfügbarkeit
    SCIPY_OK = True
except ImportError:
    SCIPY_OK = False


class ImageForensicEngine:
    """Full image forensic analysis engine."""

    def __init__(self, path, log_fn=None):
        self.path = path
        self.log = log_fn or (lambda msg, level="INFO": None)
        self.img = Image.open(path)
        self.img_rgb = self.img.convert("RGB")
        if NUMPY_OK:
            self.arr = np.array(self.img_rgb).astype(np.float64)
        else:
            self.arr = None
        self.findings = []
        self.result_images = {}

    # ── EXIF / Metadata ──────────────────────────────────────────────────────
    def extract_metadata(self):
        """Deep EXIF, IPTC, XMP metadata extraction."""
        meta = {}

        # Basic PIL info
        meta["Format"] = self.img.format or Path(self.path).suffix.upper().lstrip(".")
        meta["Mode"] = self.img.mode
        meta["Size"] = f"{self.img.width} × {self.img.height} px"
        meta["Megapixels"] = f"{(self.img.width * self.img.height) / 1e6:.2f} MP"

        if hasattr(self.img, "info"):
            for k, v in self.img.info.items():
                if k == "exif":
                    continue  # parsed separately
                if isinstance(v, (str, int, float)):
                    meta[f"Info.{k}"] = str(v)[:80]
                elif isinstance(v, bytes) and len(v) < 100:
                    meta[f"Info.{k}"] = v.hex()[:60]

        # PIL EXIF
        if EXIFTAGS_OK:
            try:
                exif_data = self.img._getexif()
                if exif_data:
                    for tag_id, val in exif_data.items():
                        tag_name = EXIF_TAGS.get(tag_id, f"Tag_{tag_id}")
                        if isinstance(val, bytes):
                            if len(val) < 60:
                                meta[f"EXIF.{tag_name}"] = val.hex()[:60]
                            else:
                                meta[f"EXIF.{tag_name}"] = f"<{len(val)} bytes>"
                        elif isinstance(val, dict):
                            # GPS info
                            for gk, gv in val.items():
                                gname = GPSTAGS.get(gk, f"GPS_{gk}")
                                meta[f"GPS.{gname}"] = str(gv)[:60]
                        elif isinstance(val, tuple) and len(val) <= 4:
                            meta[f"EXIF.{tag_name}"] = str(val)
                        else:
                            meta[f"EXIF.{tag_name}"] = str(val)[:80]
            except Exception:
                pass

        # piexif deep parse
        if PIEXIF_OK:
            try:
                exif_dict = piexif.load(self.path)
                for ifd_key in ["0th", "Exif", "GPS", "1st"]:
                    ifd = exif_dict.get(ifd_key, {})
                    if not ifd:
                        continue
                    for tag_id, val in ifd.items():
                        try:
                            tag_name = piexif.TAGS[ifd_key].get(tag_id, {}).get("name", f"Tag_{tag_id}")
                        except:
                            tag_name = f"Tag_{tag_id}"
                        key = f"piexif.{ifd_key}.{tag_name}"
                        if key not in meta:
                            if isinstance(val, bytes):
                                try:
                                    meta[key] = val.decode("utf-8", "replace")[:80]
                                except:
                                    meta[key] = val.hex()[:60] if len(val) < 40 else f"<{len(val)} bytes>"
                            else:
                                meta[key] = str(val)[:80]
            except Exception:
                pass

        # Raw binary: look for embedded strings (software, comments, URLs)
        try:
            with open(self.path, "rb") as f:
                raw = f.read()
            # Adobe, Photoshop, GIMP markers
            software_markers = [
                b"Adobe Photoshop", b"GIMP", b"Adobe Lightroom",
                b"Snapseed", b"FaceApp", b"Canva", b"Pixlr",
                b"Adobe Premiere", b"AfterEffects", b"Illustrator",
                b"photoshop", b"www.inkscape", b"Paint.NET",
                b"Screenshot", b"screen capture",
            ]
            found_sw = []
            for marker in software_markers:
                if marker.lower() in raw.lower():
                    found_sw.append(marker.decode("utf-8", "replace"))
            if found_sw:
                meta["Detected Software"] = ", ".join(set(found_sw))
                self.findings.append({
                    "type": "SOFTWARE",
                    "detail": f"Editing software detected: {', '.join(set(found_sw))}",
                    "severity": "medium"
                })

            # XMP block
            xmp_start = raw.find(b"<x:xmpmeta")
            xmp_end = raw.find(b"</x:xmpmeta>")
            if xmp_start >= 0 and xmp_end >= 0:
                xmp_data = raw[xmp_start:xmp_end + 13].decode("utf-8", "replace")
                meta["XMP"] = f"<{len(xmp_data)} chars>"
                # Extract key XMP fields
                for field in ["ModifyDate", "CreateDate", "CreatorTool",
                              "DocumentID", "OriginalDocumentID", "History"]:
                    pat = re.search(rf'(?:xmp|photoshop|tiff|dc):{field}["\s>]([^<"]+)', xmp_data, re.IGNORECASE)
                    if pat:
                        meta[f"XMP.{field}"] = pat.group(1).strip()[:80]

                # Edit history count
                history_count = len(re.findall(r'stEvt:action', xmp_data))
                if history_count > 0:
                    meta["XMP.EditHistorySteps"] = str(history_count)
                    if history_count > 1:
                        self.findings.append({
                            "type": "HISTORY",
                            "detail": f"XMP edit history: {history_count} steps recorded",
                            "severity": "medium"
                        })
        except Exception:
            pass

        return meta

    def check_metadata_consistency(self):
        """Check for metadata tampering indicators."""
        checks = []

        meta = self.extract_metadata()

        # Check create vs modify dates
        create = meta.get("EXIF.DateTimeOriginal") or meta.get("XMP.CreateDate", "")
        modify = meta.get("EXIF.DateTime") or meta.get("XMP.ModifyDate", "")
        if create and modify and create != modify:
            checks.append(("Date Mismatch", f"Create: {create[:19]} ≠ Modify: {modify[:19]}", "warn"))
            self.findings.append({
                "type": "METADATA",
                "detail": "Creation and modification dates differ",
                "severity": "medium"
            })
        elif create:
            checks.append(("Dates", "Consistent", "ok"))

        # Software check
        sw = meta.get("EXIF.Software", "") or meta.get("Detected Software", "")
        if sw:
            checks.append(("Software", sw[:40], "note"))

        # Thumbnail mismatch
        if PIEXIF_OK:
            try:
                exif_dict = piexif.load(self.path)
                thumb = exif_dict.get("thumbnail")
                if thumb:
                    thumb_img = Image.open(io.BytesIO(thumb))
                    # Compare aspect ratios
                    main_ratio = self.img.width / max(self.img.height, 1)
                    thumb_ratio = thumb_img.width / max(thumb_img.height, 1)
                    if abs(main_ratio - thumb_ratio) > 0.1:
                        checks.append(("Thumbnail", "ASPECT RATIO MISMATCH ⚠", "warn"))
                        self.findings.append({
                            "type": "THUMBNAIL",
                            "detail": f"Thumbnail aspect ratio ({thumb_ratio:.2f}) differs from main image ({main_ratio:.2f})",
                            "severity": "high"
                        })
                    else:
                        checks.append(("Thumbnail", "Consistent", "ok"))
                    self.result_images["thumbnail"] = thumb_img
            except Exception:
                pass

        # JPEG quantization tables (re-save detection)
        if self.img.format == "JPEG" or self.path.lower().endswith((".jpg", ".jpeg")):
            try:
                qt = self.img.quantization
                if qt:
                    # Check for double compression: non-standard tables
                    table_0 = list(qt.get(0, []))
                    if table_0:
                        is_standard = table_0[0] in [1, 2, 3, 4, 5, 6, 8, 16]
                        checks.append(("JPEG QT",
                                        "Standard tables" if is_standard else "Custom tables (edited)",
                                        "ok" if is_standard else "note"))
                        checks.append(("JPEG Tables", f"{len(qt)} table(s), first DC={table_0[0]}", "ok"))
            except Exception:
                pass

        # GPS data presence
        gps_keys = [k for k in meta if k.startswith("GPS.")]
        if gps_keys:
            checks.append(("GPS Data", f"{len(gps_keys)} field(s) found", "note"))
            # Try to decode lat/lon
            lat = meta.get("GPS.GPSLatitude")
            lon = meta.get("GPS.GPSLongitude")
            lat_ref = meta.get("GPS.GPSLatitudeRef", "N")
            lon_ref = meta.get("GPS.GPSLongitudeRef", "E")
            if lat and lon:
                try:
                    def _dms_to_dd(dms_str, ref):
                        # Parse ((d,1),(m,1),(s,100)) format
                        vals = re.findall(r'\((\d+),\s*(\d+)\)', str(dms_str))
                        if len(vals) >= 3:
                            d = int(vals[0][0]) / max(int(vals[0][1]), 1)
                            m = int(vals[1][0]) / max(int(vals[1][1]), 1)
                            s = int(vals[2][0]) / max(int(vals[2][1]), 1)
                            dd = d + m / 60 + s / 3600
                            if ref in ("S", "W"):
                                dd = -dd
                            return dd
                        return None
                    lat_dd = _dms_to_dd(lat, str(lat_ref))
                    lon_dd = _dms_to_dd(lon, str(lon_ref))
                    if lat_dd and lon_dd:
                        checks.append(("GPS Coords", f"{lat_dd:.6f}, {lon_dd:.6f}", "note"))
                except Exception:
                    pass
        else:
            checks.append(("GPS Data", "None (stripped or absent)", "ok"))

        return checks

    # ── Error Level Analysis (ELA) ────────────────────────────────────────────
    def error_level_analysis(self, quality=90, scale=15):
        """
        ELA: Re-save at known quality, diff with original.
        Manipulated areas show different error levels.
        """
        if not NUMPY_OK:
            self.log("NumPy required for ELA", "WARN")
            return None

        try:
            # Re-save at specified quality
            buf = io.BytesIO()
            self.img_rgb.save(buf, "JPEG", quality=quality)
            buf.seek(0)
            resaved = Image.open(buf).convert("RGB")

            # Compute difference
            ela_img = ImageChops.difference(self.img_rgb, resaved)

            # Scale up for visibility
            extrema = ela_img.getextrema()
            max_diff = max(e[1] for e in extrema) if extrema else 1
            if max_diff == 0:
                max_diff = 1

            ela_arr = np.array(ela_img).astype(np.float64)
            ela_scaled = np.clip(ela_arr * scale, 0, 255).astype(np.uint8)
            ela_result = Image.fromarray(ela_scaled)

            # Analyze for suspicious regions
            ela_gray = np.mean(ela_arr, axis=2)
            mean_err = np.mean(ela_gray)
            std_err = np.std(ela_gray)
            max_err = np.max(ela_gray)

            # Regions with significantly higher error than average
            threshold = mean_err + 2.5 * std_err
            suspicious_pixels = np.sum(ela_gray > threshold)
            total_pixels = ela_gray.size
            suspicious_pct = (suspicious_pixels / total_pixels) * 100

            if suspicious_pct > 0.5 and suspicious_pct < 30:
                self.findings.append({
                    "type": "ELA",
                    "detail": f"ELA anomaly: {suspicious_pct:.2f}% of pixels show elevated error levels",
                    "severity": "high"
                })

            # Create highlighted version
            highlight = self.img_rgb.copy().convert("RGBA")
            mask = (ela_gray > threshold).astype(np.uint8) * 140
            red_overlay = np.zeros((*ela_gray.shape, 4), dtype=np.uint8)
            red_overlay[:, :, 0] = 255
            red_overlay[:, :, 3] = mask
            overlay_img = Image.fromarray(red_overlay, "RGBA")
            highlight = Image.alpha_composite(highlight, overlay_img)

            self.result_images["ela"] = ela_result
            self.result_images["ela_highlight"] = highlight.convert("RGB")

            return {
                "mean_error": mean_err,
                "std_error": std_err,
                "max_error": max_err,
                "suspicious_pct": suspicious_pct,
                "threshold": threshold,
                "image": ela_result,
            }
        except Exception as e:
            self.log(f"ELA error: {e}", "ERR")
            return None

    # ── Channel Analysis ─────────────────────────────────────────────────────
    def channel_analysis(self):
        """Split and analyze individual color channels."""
        if not NUMPY_OK:
            return None

        try:
            r, g, b = self.img_rgb.split()

            # Statistics per channel
            stats = {}
            for name, ch in [("Red", r), ("Green", g), ("Blue", b)]:
                arr = np.array(ch).astype(np.float64)
                stats[name] = {
                    "mean": np.mean(arr),
                    "std": np.std(arr),
                    "min": int(np.min(arr)),
                    "max": int(np.max(arr)),
                    "unique": len(np.unique(arr)),
                }

            # Store channel images
            self.result_images["ch_red"] = r.convert("RGB")
            # Make proper color channel visualizations
            zero = Image.new("L", self.img.size, 0)
            self.result_images["ch_red"] = Image.merge("RGB", (r, zero, zero))
            self.result_images["ch_green"] = Image.merge("RGB", (zero, g, zero))
            self.result_images["ch_blue"] = Image.merge("RGB", (zero, zero, b))

            # Luminance
            lum = ImageOps.grayscale(self.img_rgb)
            self.result_images["luminance"] = lum.convert("RGB")

            # Edge detection (manipulation often leaves edge artifacts)
            edges = self.img_rgb.filter(ImageFilter.FIND_EDGES)
            enhancer = ImageEnhance.Contrast(edges)
            edges_enhanced = enhancer.enhance(3.0)
            self.result_images["edges"] = edges_enhanced

            return stats
        except Exception as e:
            self.log(f"Channel analysis error: {e}", "ERR")
            return None

    # ── Histogram Analysis ───────────────────────────────────────────────────
    def histogram_analysis(self):
        """Analyze histogram for signs of manipulation."""
        if not NUMPY_OK or not PIL_OK:
            return None

        try:
            hist = self.img_rgb.histogram()
            r_hist = np.array(hist[0:256])
            g_hist = np.array(hist[256:512])
            b_hist = np.array(hist[512:768])

            results = {}

            for name, h in [("Red", r_hist), ("Green", g_hist), ("Blue", b_hist)]:
                # Gap analysis: gaps in histogram indicate level adjustments
                gaps = 0
                for i in range(1, 254):
                    if h[i] == 0 and h[i - 1] > 0 and h[i + 1] > 0:
                        gaps += 1

                # Spike analysis: periodic spikes indicate resampling
                spikes = 0
                mean_h = np.mean(h[h > 0]) if np.any(h > 0) else 1
                for i in range(256):
                    if h[i] > mean_h * 5:
                        spikes += 1

                # Clipping
                clip_low = h[0] / max(np.sum(h), 1) * 100
                clip_high = h[255] / max(np.sum(h), 1) * 100

                results[name] = {
                    "gaps": gaps,
                    "spikes": spikes,
                    "clip_low_pct": clip_low,
                    "clip_high_pct": clip_high,
                }

            # Comb pattern = sign of level stretching
            total_gaps = sum(r["gaps"] for r in results.values())
            if total_gaps > 15:
                self.findings.append({
                    "type": "HISTOGRAM",
                    "detail": f"Histogram comb pattern detected ({total_gaps} gaps) — levels adjusted",
                    "severity": "medium"
                })

            # Draw histogram image
            hist_img = Image.new("RGB", (512, 200), (13, 17, 23))
            draw = ImageDraw.Draw(hist_img)

            max_val = max(max(r_hist[1:-1]), max(g_hist[1:-1]), max(b_hist[1:-1]), 1)
            for i in range(256):
                rh = int(r_hist[i] / max_val * 180)
                gh = int(g_hist[i] / max_val * 180)
                bh = int(b_hist[i] / max_val * 180)
                x = i * 2
                draw.line([(x, 195), (x, 195 - rh)], fill=(255, 60, 60, 120))
                draw.line([(x + 1, 195), (x + 1, 195 - gh)], fill=(60, 255, 60, 120))
                # Blue offset slightly
                draw.line([(x, 196), (x, 196 - bh)], fill=(60, 60, 255, 80))

            self.result_images["histogram"] = hist_img

            return results
        except Exception as e:
            self.log(f"Histogram analysis error: {e}", "ERR")
            return None

    # ── Noise Analysis ───────────────────────────────────────────────────────
    def noise_analysis(self):
        """
        Analyze noise patterns. Manipulated regions often have
        different noise characteristics than the rest of the image.
        """
        if not NUMPY_OK:
            return None

        try:
            gray = np.array(ImageOps.grayscale(self.img_rgb)).astype(np.float64)

            # High-pass filter to extract noise
            if SCIPY_OK:
                from scipy.ndimage import median_filter
                smoothed = median_filter(gray, size=3)
            else:
                smoothed_img = self.img_rgb.convert("L").filter(ImageFilter.MedianFilter(3))
                smoothed = np.array(smoothed_img).astype(np.float64)

            noise = gray - smoothed
            noise_abs = np.abs(noise)

            # Global noise stats
            global_std = np.std(noise)
            global_mean = np.mean(noise_abs)

            # Block-based noise analysis (divide into 8x8 blocks)
            block_size = 64
            h, w = gray.shape
            blocks_y = h // block_size
            blocks_x = w // block_size
            noise_map = np.zeros((blocks_y, blocks_x))

            for by in range(blocks_y):
                for bx in range(blocks_x):
                    block = noise[by * block_size:(by + 1) * block_size,
                                   bx * block_size:(bx + 1) * block_size]
                    noise_map[by, bx] = np.std(block)

            # Find blocks with significantly different noise
            map_mean = np.mean(noise_map)
            map_std = np.std(noise_map)
            anomaly_threshold = map_mean + 2.0 * map_std
            anomaly_low = max(map_mean - 2.0 * map_std, 0)

            anomaly_blocks = np.sum((noise_map > anomaly_threshold) | (noise_map < anomaly_low))
            total_blocks = noise_map.size
            anomaly_pct = (anomaly_blocks / max(total_blocks, 1)) * 100

            if anomaly_pct > 3 and anomaly_pct < 40:
                self.findings.append({
                    "type": "NOISE",
                    "detail": f"Noise inconsistency: {anomaly_pct:.1f}% of blocks show anomalous noise",
                    "severity": "medium"
                })

            # Create noise visualization
            noise_vis = np.clip(noise_abs * 10, 0, 255).astype(np.uint8)
            self.result_images["noise"] = Image.fromarray(noise_vis).convert("RGB")

            # Create noise heatmap
            if blocks_y > 0 and blocks_x > 0:
                heatmap = np.zeros((blocks_y, blocks_x, 3), dtype=np.uint8)
                for by in range(blocks_y):
                    for bx in range(blocks_x):
                        val = noise_map[by, bx]
                        if val > anomaly_threshold:
                            heatmap[by, bx] = [255, 50, 50]   # red = high anomaly
                        elif val < anomaly_low:
                            heatmap[by, bx] = [50, 50, 255]   # blue = suspiciously smooth
                        else:
                            ratio = (val - anomaly_low) / max(anomaly_threshold - anomaly_low, 0.01)
                            g = int(min(ratio * 255, 255))
                            heatmap[by, bx] = [0, g, 0]       # green = normal
                heatmap_img = Image.fromarray(heatmap).resize(
                    (w, h), Image.NEAREST)
                # Blend with original
                blend = Image.blend(self.img_rgb, heatmap_img, 0.4)
                self.result_images["noise_heatmap"] = blend

            return {
                "global_noise_std": global_std,
                "global_noise_mean": global_mean,
                "anomaly_pct": anomaly_pct,
                "block_count": total_blocks,
                "anomaly_blocks": int(anomaly_blocks),
            }
        except Exception as e:
            self.log(f"Noise analysis error: {e}", "ERR")
            return None

    # ── LSB Analysis (Steganography) ─────────────────────────────────────────
    def lsb_analysis(self):
        """
        Analyze Least Significant Bit plane for hidden data.
        Steganography tools often embed data in LSBs.
        """
        if not NUMPY_OK:
            return None

        try:
            arr = np.array(self.img_rgb)

            # Extract LSB plane
            lsb = (arr & 1) * 255
            self.result_images["lsb"] = Image.fromarray(lsb.astype(np.uint8))

            # LSB plane should be roughly random for natural images
            # Sequential patterns indicate embedded data
            lsb_flat = (arr[:, :, 0] & 1).flatten()

            # Chi-square test for randomness
            n = len(lsb_flat)
            ones = np.sum(lsb_flat)
            zeros = n - ones
            expected = n / 2
            if expected > 0:
                chi2 = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected
            else:
                chi2 = 0

            # Sequential pair analysis
            pairs = lsb_flat[:-1] == lsb_flat[1:]
            pair_ratio = np.mean(pairs)  # should be ~0.5 for random

            is_suspicious = abs(pair_ratio - 0.5) > 0.05 or chi2 > 10

            if is_suspicious:
                self.findings.append({
                    "type": "STEGANOGRAPHY",
                    "detail": f"LSB plane anomaly: pair_ratio={pair_ratio:.4f} chi²={chi2:.2f}",
                    "severity": "medium"
                })

            # Bit plane images for planes 0-7
            for bit in range(8):
                plane = ((arr[:, :, 0] >> bit) & 1) * 255
                self.result_images[f"bitplane_{bit}"] = Image.fromarray(plane.astype(np.uint8)).convert("RGB")

            # Try extracting ASCII from LSBs
            lsb_bytes = []
            bits = (arr[:, :, 0] & 1).flatten()
            for i in range(0, min(len(bits), 8000), 8):
                byte_bits = bits[i:i + 8]
                if len(byte_bits) == 8:
                    byte_val = 0
                    for b in byte_bits:
                        byte_val = (byte_val << 1) | int(b)
                    lsb_bytes.append(byte_val)

            lsb_text = ""
            for b in lsb_bytes:
                if 0x20 <= b < 0x7F:
                    lsb_text += chr(b)
                elif lsb_text and b == 0:
                    break
                else:
                    lsb_text += "."

            # Check if there's readable text
            words = re.findall(r'[a-zA-Z]{3,}', lsb_text[:200])
            if len(words) > 3:
                self.findings.append({
                    "type": "STEGANOGRAPHY",
                    "detail": f"Readable text found in LSB: ...{' '.join(words[:5])}...",
                    "severity": "high"
                })

            return {
                "chi_square": chi2,
                "pair_ratio": pair_ratio,
                "suspicious": is_suspicious,
                "lsb_sample": lsb_text[:100],
            }
        except Exception as e:
            self.log(f"LSB analysis error: {e}", "ERR")
            return None

    # ── JPEG Ghost Detection ─────────────────────────────────────────────────
    GHOST_BLOCK = 16
    GHOST_MAX_SIDE = 2048          # Ausschnitt ab (0,0) → das JPEG-Raster bleibt erhalten
    GHOST_MIN_BLOCKS = 40          # ≈ 100×100 px zusammenhängende Fläche

    def jpeg_ghost_detection(self):
        """
        JPEG ghosts (Farid 2009): the image is re-saved at many qualities. A block
        that was compressed before at quality q1 shows a clear dip in the difference
        curve at q1. A photo that was simply re-saved shows ONE such quality almost
        everywhere; a region pasted from another JPEG shows a SECOND, different
        quality as a compact area. Only that second population is reported, so a
        normal (even repeatedly re-saved) photo does not trigger.
        Only works when the pasted region is aligned to the 8×8 grid; a missing
        ghost proves nothing.
        """
        if not NUMPY_OK:
            return None
        try:
            B = self.GHOST_BLOCK
            rgb = self.img_rgb
            w, h = rgb.size
            W = min(w, self.GHOST_MAX_SIDE) // B * B
            H = min(h, self.GHOST_MAX_SIDE) // B * B
            if W < 8 * B or H < 8 * B:
                return {"ghost_detected": False, "reason": "image too small"}
            crop = rgb.crop((0, 0, W, H))
            y0 = np.asarray(crop.convert("YCbCr"), dtype=np.float32)[:, :, 0]
            qs = list(range(40, 100, 4))
            curves = []
            for q in qs:
                buf = io.BytesIO()
                crop.save(buf, "JPEG", quality=q)
                buf.seek(0)
                y1 = np.asarray(Image.open(buf).convert("YCbCr"), dtype=np.float32)[:, :, 0]
                d = (y0 - y1) ** 2
                curves.append(d.reshape(H // B, B, W // B, B).mean(axis=(1, 3)))
            C = np.stack(curves)
            last_i = int(np.argmin(C.mean(axis=(1, 2))))           # letzte Speicherqualität
            textured = y0.reshape(H // B, B, W // B, B).std(axis=(1, 3)) > 4
            top = last_i - 2                                        # nur Qualitäten ≥ 8 darunter
            ratio = np.full(C.shape[1:], 9.0)
            kbest = np.zeros(C.shape[1:], dtype=np.int32)
            strength = np.zeros(C.shape[1:])
            for k in range(1, top - 1):
                after = C[k + 1: top + 1].max(axis=0)
                r = C[k] / np.maximum(after, 1e-6)
                better = (r < ratio) & (after > 3)
                ratio[better] = r[better]
                kbest[better] = k
                strength[better] = after[better]
            dip = textured & (strength > 3) & (ratio < 0.3)
            qmap = np.where(dip, np.array(qs)[kbest], 0)
            vals, cnt = np.unique(qmap[dip], return_counts=True)
            pops = []
            for qv in [int(v) for v, _ in sorted(zip(vals, cnt), key=lambda t: -t[1])[:3]]:
                m = _open2(dip & (np.abs(qmap - qv) <= 4))
                comps = _components(m)
                if comps:
                    size, bbox = comps[0]
                    pops.append({"quality": qv, "blocks": int(m.sum()), "largest": size, "bbox": bbox})
            pops = [p for p in pops if p["blocks"] >= self.GHOST_MIN_BLOCKS]
            result = {"ghost_detected": False, "last_quality": qs[last_i],
                      "populations": [{k: p[k] for k in ("quality", "blocks", "largest")} for p in pops]}
            pair = pops[:2]
            if (len(pair) == 2 and abs(pair[0]["quality"] - pair[1]["quality"]) >= 12
                    and max(p["largest"] for p in pair) >= self.GHOST_MIN_BLOCKS):
                # die kleinere Population ist das Eingefügte – sofern sie eine echte Fläche bildet
                minor, major = sorted(pair, key=lambda p: p["blocks"])
                if minor["largest"] < self.GHOST_MIN_BLOCKS:
                    minor, major = major, minor
                by0, bx0, by1, bx1 = minor["bbox"]
                region = [bx0 * B, by0 * B, (bx1 - bx0 + 1) * B, (by1 - by0 + 1) * B]
                result.update(ghost_detected=True, ghost_quality=minor["quality"],
                              background_quality=major["quality"], region=region)
                self.findings.append({
                    "type": "JPEG_GHOST",
                    "detail": (f"JPEG ghost: region {region[2]}×{region[3]} px at ({region[0]}, {region[1]}) "
                               f"was compressed at q≈{minor['quality']}, the rest at q≈{major['quality']}"),
                    "severity": "medium"})
                vis = crop.copy()
                ImageDraw.Draw(vis).rectangle([region[0], region[1], region[0] + region[2],
                                               region[1] + region[3]], outline=(255, 42, 63), width=4)
                self.result_images["jpeg_ghost"] = vis
            return result
        except Exception as e:
            self.log(f"JPEG ghost error: {e}", "ERR")
            return None

    # ── Clone Detection ──────────────────────────────────────────────────────
    def clone_detection(self, max_side=512, bs=12, step=2):
        """
        Copy-move detection: overlapping blocks are matched by a quantised shape
        feature, verified by their pixel difference, and grouped by shift vector.
        A real clone produces ONE dominant shift with many matching blocks;
        repeating textures (tiles, windows, fences) produce many similar shifts
        and are therefore ignored.
        """
        if not NUMPY_OK:
            return None
        try:
            from numpy.lib.stride_tricks import sliding_window_view
            g = ImageOps.grayscale(self.img_rgb)
            s = max(g.size) / max_side
            if s > 1:
                g = g.resize((max(1, round(g.width / s)), max(1, round(g.height / s))), Image.BILINEAR)
            else:
                s = 1.0
            a = np.asarray(g, dtype=np.float32)
            if min(a.shape) < bs * 4:
                return {"clone_pairs": 0}
            win = sliding_window_view(a, (bs, bs))[::step, ::step]
            ny, nx = win.shape[:2]
            blocks = win.reshape(ny * nx, bs * bs)
            ys, xs = np.divmod(np.arange(ny * nx), nx)
            ys, xs = ys * step, xs * step
            keep = blocks.std(axis=1) > 5                           # flache Flächen (Himmel) auslassen
            blocks, ys, xs = blocks[keep], ys[keep], xs[keep]
            if len(blocks) < 10:
                return {"clone_pairs": 0}
            c = blocks - blocks.mean(axis=1, keepdims=True)
            feat = np.round(c.reshape(-1, 4, bs // 4, 4, bs // 4).mean(axis=(2, 4)).reshape(len(c), 16) / 6)
            feat = feat.astype(np.int32)
            order = np.lexsort(feat.T[::-1])
            shifts = {}
            for off in range(1, 7):
                i, j = order[:-off], order[off:]
                same = np.all(feat[i] == feat[j], axis=1)
                i, j = i[same], j[same]
                dy, dx = ys[j] - ys[i], xs[j] - xs[i]
                far = dy * dy + dx * dx >= 24 * 24
                i, j, dy, dx = i[far], j[far], dy[far], dx[far]
                ok = np.abs(c[i] - c[j]).mean(axis=1) < 3.0
                sgn = np.where((dy < 0) | ((dy == 0) & (dx < 0)), -1, 1)
                for a_, b_, y_, x_ in zip(i[ok], j[ok], (dy * sgn)[ok], (dx * sgn)[ok]):
                    shifts.setdefault((int(y_), int(x_)), set()).update(
                        ((int(ys[a_]), int(xs[a_])), (int(ys[b_]), int(xs[b_]))))
            if not shifts:
                return {"clone_pairs": 0}
            ranked = sorted(shifts, key=lambda k: len(shifts[k]), reverse=True)
            best = ranked[0]
            n = len(shifts[best])
            second = len(shifts[ranked[1]]) if len(ranked) > 1 else 0
            result = {"clone_pairs": 0, "best_shift_blocks": n, "runner_up_blocks": second}
            if n >= 60 and n >= 3 * second:
                pts = shifts[best]
                src = np.array([p for p in pts if (p[0] + best[0], p[1] + best[1]) in pts] or sorted(pts))
                y0_, x0_ = (src.min(axis=0) * s).astype(int)
                y1_, x1_ = ((src.max(axis=0) + bs) * s).astype(int)
                sy, sx = int(round(best[0] * s)), int(round(best[1] * s))
                result.update(clone_pairs=n // 2, shift=[sx, sy],
                              source=[int(x0_), int(y0_), int(x1_ - x0_), int(y1_ - y0_)])
                self.findings.append({
                    "type": "CLONE",
                    "detail": (f"Copy-move: a {x1_ - x0_}×{y1_ - y0_} px region was duplicated "
                               f"with shift ({sx}, {sy}) px ({n} matching blocks)"),
                    "severity": "high"})
                vis = self.img_rgb.copy()
                d = ImageDraw.Draw(vis)
                d.rectangle([x0_, y0_, x1_, y1_], outline=(255, 42, 63), width=4)
                d.rectangle([x0_ + sx, y0_ + sy, x1_ + sx, y1_ + sy], outline=(53, 255, 138), width=4)
                d.line([((x0_ + x1_) // 2, (y0_ + y1_) // 2),
                        ((x0_ + x1_) // 2 + sx, (y0_ + y1_) // 2 + sy)], fill=(255, 230, 0), width=3)
                self.result_images["clones"] = vis
            return result
        except Exception as e:
            self.log(f"Clone detection error: {e}", "ERR")
            return None

    # ── String Extraction ────────────────────────────────────────────────────
    def extract_strings(self, min_len=4):
        """Extract readable ASCII/UTF-8 strings from binary."""
        strings = []
        try:
            with open(self.path, "rb") as f:
                data = f.read()
            current = ""
            for b in data:
                if 0x20 <= b < 0x7F:
                    current += chr(b)
                else:
                    if len(current) >= min_len:
                        strings.append(current)
                    current = ""
            if len(current) >= min_len:
                strings.append(current)
        except Exception as e:
            self.log(f"String extraction error: {e}", "ERR")
        return strings

    # ── Full Analysis Pipeline ───────────────────────────────────────────────
    def run_full_analysis(self, progress_fn=None):
        report = {
            "file": self.path,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "findings": [],
        }

        if progress_fn:
            progress_fn("Extracting metadata...", 5)
        report["metadata"] = self.extract_metadata()

        if progress_fn:
            progress_fn("Checking metadata consistency...", 12)
        report["meta_checks"] = self.check_metadata_consistency()

        if progress_fn:
            progress_fn("Error Level Analysis...", 20)
        report["ela"] = self.error_level_analysis()

        if progress_fn:
            progress_fn("Channel analysis...", 35)
        report["channels"] = self.channel_analysis()

        if progress_fn:
            progress_fn("Histogram analysis...", 45)
        report["histogram"] = self.histogram_analysis()

        if progress_fn:
            progress_fn("Noise analysis...", 55)
        report["noise"] = self.noise_analysis()

        if progress_fn:
            progress_fn("LSB / Steganography scan...", 65)
        report["lsb"] = self.lsb_analysis()

        if progress_fn:
            progress_fn("JPEG ghost detection...", 78)
        if (getattr(self.img, "format", "") or "").upper() == "JPEG" or self.path.lower().endswith((".jpg", ".jpeg")):
            report["jpeg_ghost"] = self.jpeg_ghost_detection()
        else:
            report["jpeg_ghost"] = None

        if progress_fn:
            progress_fn("Clone detection...", 88)
        report["clones"] = self.clone_detection()

        report["findings"] = self.findings

        if progress_fn:
            progress_fn("Analysis complete", 100)

        return report


def _open2(m):
    """Morphologisches Öffnen mit 2×2 (entfernt Einzelblöcke)."""
    e = m[:-1, :-1] & m[1:, :-1] & m[:-1, 1:] & m[1:, 1:]
    out = np.zeros_like(m)
    out[:-1, :-1] |= e
    out[1:, :-1] |= e
    out[:-1, 1:] |= e
    out[1:, 1:] |= e
    return out


def _components(m):
    """Zusammenhängende Flächen (4er-Nachbarschaft) → [(größe, (y0, x0, y1, x1))], größte zuerst."""
    seen = np.zeros_like(m)
    h, w = m.shape
    out = []
    for y, x in zip(*np.nonzero(m)):
        if seen[y, x]:
            continue
        stack, seen[y, x] = [(y, x)], True
        n, y0, x0, y1, x1 = 0, y, x, y, x
        while stack:
            cy, cx = stack.pop()
            n += 1
            y0, x0, y1, x1 = min(y0, cy), min(x0, cx), max(y1, cy), max(x1, cx)
            for ny_, nx_ in ((cy + 1, cx), (cy - 1, cx), (cy, cx + 1), (cy, cx - 1)):
                if 0 <= ny_ < h and 0 <= nx_ < w and m[ny_, nx_] and not seen[ny_, nx_]:
                    seen[ny_, nx_] = True
                    stack.append((ny_, nx_))
        out.append((n, (int(y0), int(x0), int(y1), int(x1))))
    return sorted(out, reverse=True)
