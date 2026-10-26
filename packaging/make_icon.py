"""Draws the app icon (ONE above CONFIG, in the Diorama theme's colours) and writes packaging/OneConfig.icns.
Needs the dev extras (Playwright's Chromium) and macOS's sips and iconutil. From the project root:
    .venv/bin/python packaging/make_icon.py"""
import subprocess
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).parent
# macOS icon grid: an 824px rounded square centred on a 1024px canvas, with room for its shadow
PAGE = """<!doctype html><meta charset="utf-8"><style>
html,body{margin:0;width:1024px;height:1024px;background:transparent}
.tile{position:absolute;left:100px;top:100px;width:824px;height:824px;border-radius:185px;overflow:hidden;
  background:radial-gradient(70% 60% at 22% 0%,rgba(255,214,150,.30),transparent 70%),
             radial-gradient(60% 50% at 95% 105%,rgba(70,110,170,.30),transparent 70%),#0d0f15;
  box-shadow:0 18px 36px rgba(0,0,0,.45),inset 0 0 0 3px rgba(232,214,170,.28)}
.c{position:absolute;width:74px;height:74px;border:solid #e8cf8a;opacity:.85}
.c.tl{left:92px;top:92px;border-width:7px 0 0 7px}.c.tr{right:92px;top:92px;border-width:7px 7px 0 0}
.c.bl{left:92px;bottom:92px;border-width:0 0 7px 7px}.c.br{right:92px;bottom:92px;border-width:0 7px 7px 0}
.word{position:absolute;left:0;right:0;text-align:center;font-family:Palatino,"Palatino Linotype","Book Antiqua",Georgia,serif}
.one{top:228px;font-size:228px;line-height:1;letter-spacing:.10em;text-indent:.10em;color:#e8cf8a;text-shadow:0 6px 18px rgba(0,0,0,.55)}
.rule{position:absolute;left:236px;right:236px;top:486px;height:5px;background:linear-gradient(90deg,transparent,#e8cf8a 18%,#e8cf8a 82%,transparent)}
.config{top:530px;font-size:112px;line-height:1;letter-spacing:.16em;text-indent:.16em;color:#f3eee2;text-shadow:0 4px 12px rgba(0,0,0,.55)}
</style><div class="tile"><i class="c tl"></i><i class="c tr"></i><i class="c bl"></i><i class="c br"></i>
<div class="word one">ONE</div><div class="rule"></div><div class="word config">CONFIG</div></div>"""


def main():
    png = HERE / "icon-1024.png"
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1024, "height": 1024})
        pg.set_content(PAGE)
        pg.screenshot(path=str(png), omit_background=True)
        b.close()
    with tempfile.TemporaryDirectory() as tmp:
        iconset = Path(tmp) / "OneConfig.iconset"
        iconset.mkdir()
        for size in (16, 32, 128, 256, 512):
            for scale in (1, 2):
                name = f"icon_{size}x{size}{'@2x' if scale == 2 else ''}.png"
                subprocess.run(["sips", "-z", str(size * scale), str(size * scale), str(png), "--out", str(iconset / name)],
                               check=True, capture_output=True)
        subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(HERE / "OneConfig.icns")], check=True)
    print(f"wrote {png} and {HERE / 'OneConfig.icns'}")


if __name__ == "__main__":
    main()
