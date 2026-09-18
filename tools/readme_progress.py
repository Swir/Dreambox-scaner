#!/usr/bin/env python3
"""Generate/check SWIR README progress SVGs for Dreambox Scanner."""
from __future__ import annotations
from pathlib import Path
import argparse, re
ROOT=Path(__file__).resolve().parents[1]
NAME="DREAMBOX SCANNER"
CARD=ROOT/"assets/readme/progress-card.svg"
MINI=ROOT/"assets/readme/progress-mini.svg"
README=ROOT/"README.md"
def card():
 return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="180" viewBox="0 0 1200 180" role="img" aria-labelledby="title desc">\n<title id="title">{NAME} product progress</title><desc id="desc">Product progress is N/A because this repository has no canonical measurable product roadmap.</desc>\n<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#02050A"/><stop offset="1" stop-color="#07111C"/></linearGradient><linearGradient id="c" x1="0" y1="0" x2="1" y2="0"><stop stop-color="#0088FF"/><stop offset="1" stop-color="#62E5FF"/></linearGradient></defs>\n<rect x="1" y="1" width="1198" height="178" rx="22" fill="url(#bg)" stroke="#62E5FF" stroke-opacity=".25"/>\n<text x="50" y="38" fill="#62E5FF" font-family="Segoe UI,Arial,sans-serif" font-size="15" font-weight="700" letter-spacing="3">SWIR PROGRESS</text>\n<text x="50" y="72" fill="#F4FAFF" font-family="Segoe UI,Arial,sans-serif" font-size="27" font-weight="800">{NAME}</text>\n<text x="50" y="97" fill="#8DA8B8" font-family="Segoe UI,Arial,sans-serif" font-size="14">Measured scope: product progress</text>\n<rect x="50" y="116" width="1100" height="20" rx="10" fill="#08131F" stroke="#62E5FF" stroke-opacity=".16"/>\n<path d="M70 126H1130" stroke="url(#c)" stroke-width="2" stroke-dasharray="8 12" opacity=".32"/>\n<text x="50" y="158" fill="#8DA8B8" font-family="Segoe UI,Arial,sans-serif" font-size="12">Status: no canonical measurable roadmap · progress counter unavailable</text>\n<text x="1145" y="96" text-anchor="end" fill="#F4FAFF" font-family="Segoe UI,Arial,sans-serif" font-size="34" font-weight="800">N/A</text>\n</svg>\n'''
def mini():
 return f'''<svg xmlns="http://www.w3.org/2000/svg" width="900" height="72" viewBox="0 0 900 72" role="img" aria-labelledby="title desc">\n<title id="title">{NAME} product progress</title><desc id="desc">Product progress is N/A because this repository has no canonical measurable product roadmap.</desc>\n<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#02050A"/><stop offset="1" stop-color="#07111C"/></linearGradient></defs>\n<rect x="1" y="1" width="898" height="70" rx="15" fill="url(#bg)" stroke="#62E5FF" stroke-opacity=".25"/>\n<text x="24" y="28" fill="#F4FAFF" font-family="Segoe UI,Arial,sans-serif" font-size="14" font-weight="700">{NAME}</text>\n<text x="24" y="50" fill="#8DA8B8" font-family="Segoe UI,Arial,sans-serif" font-size="11">Product progress · no canonical measurable roadmap</text>\n<rect x="430" y="27" width="360" height="16" rx="8" fill="#08131F" stroke="#62E5FF" stroke-opacity=".15"/>\n<text x="865" y="43" text-anchor="end" fill="#62E5FF" font-family="Segoe UI,Arial,sans-serif" font-size="18" font-weight="800">N/A</text>\n</svg>\n'''
def legacy(text): return bool(re.search(r"[█▓▒░]{5,}|\[(?:\s*[#=\-]){6,}\s*\]",text))
def expected(): return {CARD:card(),MINI:mini()}
def check():
 ok=True
 for p,w in expected().items():
  if not p.exists() or p.read_text(encoding="utf-8")!=w: print("stale or missing:",p.relative_to(ROOT)); ok=False
 r=README.read_text(encoding="utf-8")
 for rel in ("assets/readme/progress-card.svg","assets/readme/progress-mini.svg"):
  if rel not in r: print("README missing embed:",rel); ok=False
 if legacy(r): print("README contains a retired character progress meter"); ok=False
 return 0 if ok else 1
def main():
 a=argparse.ArgumentParser(); a.add_argument("--check",action="store_true"); args=a.parse_args()
 if not args.check:
  for p,c in expected().items(): p.parent.mkdir(parents=True,exist_ok=True); p.write_text(c,encoding="utf-8")
 return check()
if __name__=="__main__": raise SystemExit(main())
