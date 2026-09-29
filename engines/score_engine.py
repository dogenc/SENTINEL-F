"""
╔══════════════════════════════════════════════════════════════╗
║           MANIPULATION SCORE ENGINE — 0-100                  ║
║  Heuristic assessment with optional Ollama second-opinion    ║
╚══════════════════════════════════════════════════════════════╝

The ScoreEngine consumes the structured report produced by each forensic
engine (image / pdf / document) and emits:
  - score:     0-100 (0 = clean, 100 = critical manipulation indicators)
  - level:     CLEAN | LOW RISK | ELEVATED | HIGH RISK | CRITICAL
  - color:     theme key
  - findings:  list of {code, weight, desc, severity}
  - summary:   top 3-5 strongest signals

The individual weights come from config.SCORE_WEIGHTS so thresholds can
be tuned without touching logic.
"""
from config.settings import SCORE_WEIGHTS as W, SCORE_LEVELS, T


class ScoreEngine:
    def __init__(self):
        self.findings = []

    # ─── Public API ───────────────────────────────────────────────────────
    def score_image(self, report):
        """Consume ImageForensicEngine.run_full_analysis() output."""
        self.findings = []
        self._image_checks(report)
        return self._finalize()

    def score_pdf(self, report):
        """Consume PDF analysis dictionary."""
        self.findings = []
        self._pdf_checks(report)
        return self._finalize()

    def score_document(self, report):
        """Consume DocumentForensicEngine.run_full_analysis() output."""
        self.findings = []
        self._document_checks(report)
        return self._finalize()

    def score_findings(self, findings, base=None):
        """Bewertet Analysator-Findings, optional zusammen mit bereits
        gewichteten Findings einer klassischen Engine (base)."""
        self.findings = list(base or [])
        seen = {}
        for f in findings or []:
            code = f.get("code", "?")
            self._add(code, f.get("desc", ""), f.get("severity", "INFO"), source=f.get("source"))
            added = self.findings[-1]
            # Hinweise sind Kontext, kein Risiko: viele INFOs dürfen nie CRITICAL ergeben
            if added["severity"] == "INFO":
                added["weight"] = round(added["weight"] * 0.3, 1)
            # Wiederholungen desselben Codes zählen abnehmend (1, ½, ¼ …)
            n = seen.get(code, 0)
            if n:
                added["weight"] = round(added["weight"] / (2 ** n), 1)
            seen[code] = n + 1
        return self._finalize()

    # ─── Image checks ─────────────────────────────────────────────────────
    def _image_checks(self, r):
        meta = (r or {}).get("metadata") or {}
        cons = (r or {}).get("consistency") or {}
        ela  = (r or {}).get("ela") or {}
        ghost= (r or {}).get("jpeg_ghost") or {}
        clone= (r or {}).get("clone") or {}
        lsb  = (r or {}).get("lsb") or {}

        # Metadata stripped?
        has_exif = bool(meta.get("exif")) or bool(meta.get("exif_piexif"))
        if not has_exif and (meta.get("format") or "").upper() == "JPEG":
            self._add("metadata_stripped", "EXIF metadata absent on JPEG (stripped or never present)", "WARN")

        # Consistency issues
        for issue in (cons.get("issues") or []):
            sev = issue.get("severity", "WARN").upper()
            code = "metadata_inconsistent"
            if "timestamp" in issue.get("msg", "").lower() or "date" in issue.get("msg", "").lower():
                code = "timestamp_anomaly"
            if "thumbnail" in issue.get("msg", "").lower():
                code = "thumbnail_mismatch"
            self._add(code, issue.get("msg", "consistency issue"), sev)

        # ELA — high manipulation signal
        if ela:
            mean = ela.get("mean", 0)
            maxv = ela.get("max", 0)
            if mean > 18 or maxv > 190:
                self._add("ela_high", f"ELA elevated (mean={mean:.1f}, max={maxv})", "CRIT")
            elif mean > 10:
                self._add("ela_high", f"ELA moderately elevated (mean={mean:.1f})", "WARN")

        # JPEG ghost
        if ghost.get("ghost_detected"):
            x, y, w, h = ghost.get("region") or (0, 0, 0, 0)
            self._add("jpeg_ghost", f"Region {w}×{h} px at ({x}, {y}) carries a second JPEG quality "
                      f"(q≈{ghost.get('ghost_quality')} vs. q≈{ghost.get('background_quality')}): likely pasted in",
                      "WARN")

        # Clone (copy-move)
        if clone.get("clone_pairs", 0) > 0:
            x, y, w, h = clone.get("source") or (0, 0, 0, 0)
            dx, dy = clone.get("shift") or (0, 0)
            self._add("clone_detected", f"Copy-move: {w}×{h} px region at ({x}, {y}) duplicated "
                      f"with shift ({dx}, {dy}) px", "CRIT")

        # LSB stego suspicion
        if lsb.get("suspicious"):
            self._add("lsb_anomaly", f"LSB distribution suspicious (score={lsb.get('score', 0):.2f})", "WARN")

        # Hash mismatch (if original_hash supplied for verification)
        if (r or {}).get("hash_mismatch"):
            self._add("hash_mismatch", "Hash mismatch vs. reference", "CRIT")

    # ─── PDF checks ───────────────────────────────────────────────────────
    def _pdf_checks(self, r):
        info = (r or {}).get("info") or {}
        meta = (r or {}).get("metadata") or {}

        if info.get("has_javascript") or (r or {}).get("javascript"):
            self._add("javascript", "PDF contains JavaScript", "WARN")

        if info.get("is_encrypted"):
            self._add("encryption_inconsistent", "PDF encryption present", "INFO")

        redactions = (r or {}).get("redactions") or []
        if redactions:
            self._add("redactions", f"{len(redactions)} redaction annotation(s) found", "WARN")

        blackrects = (r or {}).get("black_rectangles", 0)
        if blackrects and blackrects > 0:
            self._add("black_rectangles", f"{blackrects} suspicious black rectangle(s) in content stream", "WARN")

        if (r or {}).get("unused_objects", 0) > 10:
            self._add("unused_objects", f"{r['unused_objects']} unused/dangling objects (possible hidden data)", "INFO")

        # Metadata consistency
        if meta.get("producer") and meta.get("creator"):
            if meta["producer"].lower() != meta["creator"].lower():
                # Different tool chain — not necessarily bad, but worth noting
                pass
        if meta.get("mod_date") and meta.get("create_date"):
            if meta["mod_date"] != meta["create_date"]:
                self._add("timestamp_anomaly", "PDF created-date differs from modified-date", "INFO")

        if (r or {}).get("hash_mismatch"):
            self._add("hash_mismatch", "Hash mismatch vs. reference", "CRIT")

    # ─── Document checks ──────────────────────────────────────────────────
    def _document_checks(self, r):
        macros = (r or {}).get("macros") or {}
        hidden = (r or {}).get("hidden") or {}
        objs   = (r or {}).get("objects") or {}
        rels   = (r or {}).get("relationships") or {}
        revs   = (r or {}).get("revisions") or {}
        ent    = (r or {}).get("entropy") or {}

        if macros.get("has_macros"):
            self._add("macro_present", "VBA macros present", "WARN")
        if macros.get("suspicious_keywords"):
            kw = macros["suspicious_keywords"]
            if isinstance(kw, (list, tuple)) and kw:
                self._add("macro_suspicious",
                          f"Suspicious macro keywords: {', '.join(kw[:5])}", "CRIT")

        if hidden.get("count", 0) > 0:
            self._add("hidden_content", f"{hidden['count']} hidden item(s) detected", "WARN")

        if objs.get("count", 0) > 0:
            self._add("embedded_objects", f"{objs['count']} embedded object(s)", "INFO")

        if revs.get("count", 0) > 0:
            self._add("revision_history", f"{revs['count']} tracked revision(s)", "INFO")

        ext_rels = rels.get("external", [])
        if ext_rels:
            self._add("external_relationship",
                      f"{len(ext_rels)} external relationship(s) (templates/remote refs)", "WARN")

        if ent.get("overall", 0) > 7.5:
            self._add("entropy_suspicious", f"High overall entropy ({ent['overall']:.2f})", "INFO")

        if (r or {}).get("hash_mismatch"):
            self._add("hash_mismatch", "Hash mismatch vs. reference", "CRIT")

    # ─── Helpers ──────────────────────────────────────────────────────────
    def _add(self, code, desc, severity="INFO", source=None):
        weight = W.get(code, 0)
        # severity multiplier
        mul = {"INFO": 0.5, "WARN": 1.0, "CRIT": 1.3}.get(severity.upper(), 1.0)
        f = {
            "code": code,
            "desc": desc,
            "severity": severity.upper(),
            "weight": round(weight * mul, 1),
        }
        if source:
            f["source"] = source
        self.findings.append(f)

    def _finalize(self):
        raw = sum(f["weight"] for f in self.findings)
        score = min(100, int(round(raw)))
        level, color_key = self._level_for(score)

        # Top signals
        top = sorted(self.findings, key=lambda x: x["weight"], reverse=True)[:5]

        return {
            "score":    score,
            "level":    level,
            "color":    T[color_key],
            "color_key": color_key,
            "findings": self.findings,
            "top":      top,
            "total_signals": len(self.findings),
        }

    def _level_for(self, score):
        best = SCORE_LEVELS[0]
        for threshold, label, key in SCORE_LEVELS:
            if score >= threshold:
                best = (threshold, label, key)
        return best[1], best[2]
