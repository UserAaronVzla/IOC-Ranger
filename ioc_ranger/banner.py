from __future__ import annotations
from typing import Tuple
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.box import ROUNDED
from rich.style import Style


ASCII = r"""
by Aaron E. (UserAaronVzla)
█████    ███████      █████████     ███████████                                                   
░░███   ███░░░░░███   ███░░░░░███   ░░███░░░░░███                                                  
 ░███  ███     ░░███ ███     ░░░     ░███    ░███   ██████   ████████    ███████  ██████  ████████ 
 ░███ ░███      ░███░███             ░██████████   ░░░░░███ ░░███░░███  ███░░███ ███░░███░░███░░███
 ░███ ░███      ░███░███             ░███░░░░░███   ███████  ░███ ░███ ░███ ░███░███████  ░███ ░░░ 
 ░███ ░░███     ███ ░░███     ███    ░███    ░███  ███░░███  ░███ ░███ ░███ ░███░███░░░   ░███     
 █████ ░░░███████░   ░░█████████     █████   █████░░████████ ████ █████░░███████░░██████  █████    
░░░░░    ░░░░░░░      ░░░░░░░░░     ░░░░░   ░░░░░  ░░░░░░░░ ░░░░ ░░░░░  ░░░░░███ ░░░░░░  ░░░░░     
                                                                        ███ ░███                   
                                                                       ░░██████                    
                                                                        ░░░░░░                     
                                                                                                   
                                                                                                   
"""                                                                                                   
# ── Helpers (gradient + badges) ───────────────────────────────────────────────
def _hex_to_rgb(h: str) -> Tuple[int, int, int]:
    h = h.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)

def _lerp(a: int, b: int, t: float) -> int:
    return int(a + (b - a) * t)

def _gradient_text(block: str, c1: str = "#00d1ff", c2: str = "#7c3aed") -> Text:
    start = _hex_to_rgb(c1)
    end = _hex_to_rgb(c2)
    lines = block.splitlines(keepends=True)
    widest = max((len(l.rstrip("\n")) for l in lines), default=1)
    out = Text()
    for line in lines:
        core = line.rstrip("\n")
        for i, ch in enumerate(core):
            t = i / max(widest - 1, 1)
            r = _lerp(start[0], end[0], t)
            g = _lerp(start[1], end[1], t)
            b = _lerp(start[2], end[2], t)
            out.append(ch, Style(color=f"#{r:02x}{g:02x}{b:02x}", bold=True))
        out.append("\n")
    return out

def _badges() -> Text:
    badges = Text()
    badges.append(" VT ", style="bold white on #0ea5e9")            # VirusTotal
    badges.append("  AbuseIPDB ", style="bold black on #facc15")    # AbuseIPDB
    badges.append("  IPQualityScore ", style="bold white on #22c55e")  # IPQS
    return badges

# ── Public API ────────────────────────────────────────────────────────────────
def print_banner(version: str= "1.0.0" | None = None, color1: str = "#00d1ff", color2: str = "#7c3aed") -> None:
    """
    Render the IOC Ranger banner.
    - version: optional string like "1.0.0" (shown in subtitle)
    - color1/color2: hex colors for the gradient
    """
    console = Console()
    title = _gradient_text(ASCII, c1=color1, c2=color2)

    panel = Panel(
        Align.center(title),
        title="[bold magenta]IOC Ranger[/bold magenta]",
        subtitle=(
            "[white]Reputation • Signatures • VPN/Proxy • Reports[/white]"
            + (f"   [#94a3b8]v{version}[/#94a3b8]" if version else "")
        ),
        border_style=color2,
        box=ROUNDED,
        padding=(1, 2),
    )
    console.print(panel)
    console.print(Align.center(_badges()))
    console.print()  # spacer                                                                                                   
                                                                                                   
