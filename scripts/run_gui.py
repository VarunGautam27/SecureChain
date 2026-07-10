"""Launches the local SecureChain GUI at http://127.0.0.1:5678 and opens it
in the default browser. This is a local preview layer only. Pushing from the
GUI still triggers the same GitHub Actions workflow, and that CI run remains
the only result that actually blocks a merge.
"""

from __future__ import annotations

import threading
import webbrowser

from securechain.gui.server import create_app

HOST = "127.0.0.1"
PORT = 5678


def main() -> None:
    app = create_app()
    url = f"http://{HOST}:{PORT}"
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    print(f"SecureChain GUI running at {url}")
    print("Press Control C to stop.")
    app.run(host=HOST, port=PORT, debug=False)


if __name__ == "__main__":
    main()
