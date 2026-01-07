import threading
import time
from rich.live import Live
from ui.live_ui import render_layout
from capture.sniffer import start_sniffer

def main():
    # 🔥 Start sniffer in background thread
    sniffer_thread = threading.Thread(
        target=start_sniffer,
        kwargs={"interface": "wlan0"},
        daemon=True
    )
    sniffer_thread.start()

    # 🔥 Rich Live UI loop
    with Live(render_layout(), refresh_per_second=4, screen=True) as live:
        while True:
            live.update(render_layout())
            time.sleep(0.25)   # IMPORTANT: yield CPU

if __name__ == "__main__":
    main()
