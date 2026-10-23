"""Builds the backend into one executable and drops it where Tauri expects its sidecar.

  backend/.venv/Scripts/python build_sidecar.py      (needs: pip install pyinstaller)
Then: cd frontend && npm run tauri build
"""
import re
import shutil
import subprocess
import sys
from pathlib import Path

here = Path(__file__).parent
build = here.parent / "build"
subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--onefile", "--name", "coven-backend",
                "--distpath", build / "bin", "--workpath", build / "pyi", "--specpath", build,
                "--collect-all", "litellm", "--collect-all", "tiktoken_ext", "--hidden-import", "tiktoken_ext.openai_public",
                "--collect-submodules", "uvicorn", here / "server.py"], check=True, cwd=here)
triple = re.search(r"host: (\S+)", subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True).stdout)[1]
ext = ".exe" if sys.platform == "win32" else ""
dest = here.parent / "frontend" / "src-tauri" / "binaries" / f"coven-backend-{triple}{ext}"
dest.parent.mkdir(exist_ok=True)
shutil.copy2(build / "bin" / f"coven-backend{ext}", dest)
print(f"sidecar -> {dest}")
