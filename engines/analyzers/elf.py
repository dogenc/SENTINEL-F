"""Linux/Unix-Programme (ELF): Architektur, Typ, gestrippt, Packer, Sections."""
import math
from collections import Counter

from .base import finding


def _entropy(buf):
    if not buf:
        return 0.0
    c, n = Counter(buf), len(buf)
    return -sum(v / n * math.log2(v / n) for v in c.values())


class ElfAnalyzer:
    name = "elf"

    def applies(self, ctx):
        return ctx.subtype == "elf"

    def run(self, ctx):
        from elftools.elf.elffile import ELFFile
        findings, d = [], {}
        with open(ctx.path, "rb") as f:
            elf = ELFFile(f)
            d["class"] = f"{elf.elfclass}-bit"
            d["machine"] = elf["e_machine"]
            d["type"] = elf["e_type"]
            d["entry"] = hex(elf["e_entry"])
            secs, names = [], set()
            for s in elf.iter_sections():
                names.add(s.name)
                data = s.data()[:4 << 20] if s["sh_type"] != "SHT_NOBITS" else b""
                secs.append({"name": s.name, "type": s["sh_type"], "size": s["sh_size"],
                             "entropy": round(_entropy(data), 3), "flags": s["sh_flags"]})
            d["sections"] = secs[:80]
            d["stripped"] = ".symtab" not in names
            d["interpreter"] = None
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_INTERP":
                    d["interpreter"] = seg.get_interp_name()
                if seg["p_type"] == "PT_LOAD" and seg["p_flags"] & 0x3 == 0x3:
                    findings.append(finding("elf_wx_segment", "Speichersegment beschreibbar UND ausführbar", "WARN"))
            libs = []
            dyn = elf.get_section_by_name(".dynamic")
            if dyn is not None:
                libs = [t.needed for t in dyn.iter_tags() if t.entry.d_tag == "DT_NEEDED"]
            d["libraries"] = libs
        if not secs:
            findings.append(finding("elf_no_sections", "Keine Section-Tabelle (entfernt – typisch für gepackte Malware)", "WARN"))
        if b"UPX!" in ctx.data[:4096] or b"UPX!" in ctx.data[-4096:]:
            d["packer"] = "UPX"
            findings.append(finding("pe_packed", "Mit UPX gepackt", "WARN"))
        if d["type"] == "ET_EXEC" and not d["interpreter"] and not libs:
            findings.append(finding("elf_static", "Statisch gelinkt (häufig bei Botnet-Malware wie Mirai)", "INFO"))
        return {"data": d, "findings": findings}
