# controller/controller.py

import threading
import time

class IDSController:
    def __init__(self):
        self.running = False
        self.lock = threading.Lock()

        self.packet_count = 0
        self.tcp_syn = 0
        self.icmp = 0
        self.baseline_learning = True

    def start(self):
        self.running = True
        threading.Thread(target=self._printer, daemon=True).start()

    def stop(self):
        self.running = False

    def count_packet(self, parsed):
        with self.lock:
            self.packet_count += 1

            if parsed.get("protocol") == "ICMP":
                self.icmp += 1

            if parsed.get("tcp_flags") == "S":
                self.tcp_syn += 1

    def set_baseline_status(self, learning):
        self.baseline_learning = learning

    def _printer(self):
        while self.running:
            time.sleep(1)

            with self.lock:
                if self.packet_count == 0:
                    continue   # 🚫 DO NOT PRINT ZERO SPAM

                print(
                    f"Packets/sec: {self.packet_count} | "
                    f"TCP SYN: {self.tcp_syn} | "
                    f"ICMP: {self.icmp} | "
                    f"Baseline: {'LEARNING' if self.baseline_learning else 'ACTIVE'}"
                )

                self.packet_count = 0
                self.tcp_syn = 0
                self.icmp = 0


controller = IDSController()
