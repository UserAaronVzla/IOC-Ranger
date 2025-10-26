from .banner import print_banner
from . import __version__ as VERSION

# ...
if not no_banner:
    print_banner(version=VERSION)  # or pick your colors: print_banner(VERSION, "#22d3ee", "#6366f1")
