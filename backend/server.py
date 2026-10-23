"""Entry point of the packaged backend: python server.py [port] [--exit-with-stdin].

The desktop app starts it as a sidecar with --exit-with-stdin: when the app goes away its end of the stdin
pipe closes and we exit too (killing a PyInstaller one-file exe only stops the bootloader, not this process)."""
import os
import subprocess
import sys
import threading

import uvicorn

from app.main import app

if sys.platform == "win32":
    # The sidecar has no console, so every CLI it runs (git, claude, npm...) would pop up its own window.
    _popen_init = subprocess.Popen.__init__

    def _no_window(self, *args, **kwargs):
        kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)
        _popen_init(self, *args, **kwargs)

    subprocess.Popen.__init__ = _no_window

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--exit-with-stdin" in sys.argv:
        threading.Thread(target=lambda: (sys.stdin.read(), os._exit(0)), daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=int(args[0]) if args else 8000)
