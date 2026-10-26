# PyInstaller build for the macOS app. From the project root:
#   .venv/bin/pyinstaller packaging/OneConfig.spec --noconfirm
# Output: dist/OneConfig.app (unsigned; first open with right-click > Open).
import os

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules, copy_metadata

datas = collect_data_files("oneconfig")  # templates, the page, examples, STIG rules
datas += collect_data_files("ntc_templates")  # TextFSM templates that parse show output in discovery and push checks
datas += copy_metadata("ntc_templates")  # it reads its own version on import: without this, discovery and push fail
binaries, hiddenimports = [], ["keyring.backends.macOS"]  # keyring finds its backends by entry point, which analysis can't see
for pkg in ("pysnmp", "netmiko"):  # pysnmp loads its MIB modules by name at runtime; netmiko picks a driver per OS
    d, b, h = collect_all(pkg)
    datas, binaries, hiddenimports = datas + d, binaries + b, hiddenimports + h
hiddenimports += collect_submodules("oneconfig")

a = Analysis([os.path.join(SPECPATH, "launch.py")], pathex=[os.path.join(SPECPATH, "..")], datas=datas, binaries=binaries, hiddenimports=hiddenimports,
             excludes=["tkinter", "pytest", "playwright", "IPython"])
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="OneConfig", console=False, upx=False)
coll = COLLECT(exe, a.binaries, a.datas, name="OneConfig", upx=False)
app = BUNDLE(
    coll,
    name="OneConfig.app",
    bundle_identifier="io.github.chrischarrisofficial-tech.oneconfig",
    version="0.1.0",
    info_plist={
        "CFBundleDisplayName": "OneConfig",
        "CFBundleShortVersionString": "0.1.0",
        "LSMinimumSystemVersion": "11.0",
        "NSHighResolutionCapable": True,
        # Discovery, SSH and SNMP reach devices on your network; macOS asks once, with this reason.
        "NSLocalNetworkUsageDescription": "OneConfig connects to routers, switches and firewalls on your network "
                                          "to discover them, read their configuration and push changes you approve.",
        # The window loads the app from its own server on 127.0.0.1.
        "NSAppTransportSecurity": {"NSAllowsLocalNetworking": True},
    },
)
