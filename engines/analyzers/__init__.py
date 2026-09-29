"""
Registry aller Analysatoren. Neuer Dateityp = neues Modul + Eintrag hier.
Reihenfolge: baseline zuerst (teilt IOCs), YARA zuletzt.
"""
from .base import FileContext, run_all
from .baseline import BaselineAnalyzer
from .archive import ArchiveAnalyzer
from .pe import PEAnalyzer
from .elf import ElfAnalyzer
from .script import ScriptAnalyzer
from .web import WebAnalyzer
from .lnk import LnkAnalyzer
from .rtf import RtfAnalyzer
from .mail import EmailAnalyzer
from .sqlite import SqliteAnalyzer
from .yara_scan import YaraAnalyzer
from .photo import PhotoAnalyzer
from .lineage import LineageAnalyzer


def default_analyzers():
    return [
        BaselineAnalyzer(),
        PhotoAnalyzer(),
        LineageAnalyzer(),
        ArchiveAnalyzer(),
        PEAnalyzer(),
        ElfAnalyzer(),
        ScriptAnalyzer(),
        WebAnalyzer(),
        LnkAnalyzer(),
        RtfAnalyzer(),
        EmailAnalyzer(),
        SqliteAnalyzer(),
        YaraAnalyzer(),
    ]


__all__ = ["FileContext", "run_all", "default_analyzers"]
