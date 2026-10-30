"""Link Safety Inspector - pause before you click, offline.

A small tool by Asdale Dynamics, LLC that checks pasted links or saved
email text files for suspicious patterns, entirely on your own machine.
"""

__version__ = "0.1.0"

__all__ = ["analyze", "extract_urls", "__version__"]


def __getattr__(name):
    if name == "analyze":
        from .analyzer import analyze

        return analyze
    if name == "extract_urls":
        from .extract import extract_urls

        return extract_urls
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
