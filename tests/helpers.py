from core.filetype import identify
from engines.analyzers import FileContext, run_all, default_analyzers


def analyze(path, only=None):
    ctx = FileContext(path, identify(path))
    analyzers = [a for a in default_analyzers() if only is None or a.name in only]
    data, findings = run_all(ctx, analyzers)
    return data, findings


def codes(findings):
    return {f["code"] for f in findings}
