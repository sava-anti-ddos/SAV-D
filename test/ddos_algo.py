import random
import time


class DDoS:

    def __init__(self):
        self.baseline = {}
        self.count_array = {}
        self.window_left = 0
        self.window_right = 0
        self.window_interval = 0
        self.threshold = 100
        self.ddos_dectection_order = 0

    def detect_ddos(self, data):
        """
        Detects a DDoS attack.

        Args:
            data (list): The data to be analyzed.

        Returns:
            bool: True if a DDoS attack is detected, False otherwise.
        """
        self.ddos_dectection_order += 1
        try:
            for row in data:
                (sip, dip, sport, dport, protocol, flags, timestamp,
                 length) = row

                if self.window_left == 0:
                    self.window_left = timestamp

                if timestamp > self.window_right:
                    self.window_right = timestamp

                if not sip or not dip:
                    continue
                # Check if the packet is part of a DDoS attack
                if (sip, dip, timestamp) not in self.count_array.keys():
                    self.count_array[(sip, dip, timestamp)] = 0
                self.count_array[(sip, dip, timestamp)] += 1

            print(
                f"{self.ddos_dectection_order} Count array number: {len(self.count_array)}"
            )

            for key in list(self.count_array.keys()):
                (sip, dip, t) = key
                # clean up the count array
                if t < self.window_left:
                    del self.count_array[key]
                    continue
                if (sip, dip) not in self.baseline:
                    self.baseline[(sip, dip)] = 0

                self.baseline[(sip, dip)] += self.count_array[key]

            for key in self.baseline.keys():
                (sip, dip) = key
                if self.baseline[key] > self.threshold:
                    print(
                        f"{self.ddos_dectection_order} baseline({sip, dip}): {self.baseline[key]}"
                    )
                    print(
                        f"{self.ddos_dectection_order} DDoS attack detected from {sip} to {dip}"
                    )
                    # self.rule_issuance.send_rules([sip])

            print(
                f"{self.ddos_dectection_order} Count array number: {len(self.count_array)}"
            )
            self.window_interval = self.window_right - self.window_left
            print(
                f"{self.ddos_dectection_order} Window left: {self.window_left}")
            print(
                f"{self.ddos_dectection_order} Window right: {self.window_right}"
            )
            # print(f"{self.ddos_dectection_order} Baseline: {self.baseline}")
            print(
                f"{self.ddos_dectection_order} Window interval: {self.window_interval}"
            )
            self.window_left = self.window_right
            # reset the baseline
            self.baseline = {}
        except Exception as e:
            print(f"{self.ddos_dectection_order} Error in detect_ddos: {e}")


if __name__ == "__main__":
    ddos = DDoS()
    data1 = [["192.168.10.2", "10.10.0.2", 80, 80, "TCP", "SYN", x, 100]
             for x in range(1000)]
    data2 = [["192.168.10.2", "10.10.0.2", 80, 80, "TCP", "SYN", x, 100]
             for x in range(2000)
             if x > 1000]
    ddos.detect_ddos(data1)
    ddos.detect_ddos(data2)
    # random data to test ddos detection
    data3 = []
    for x in range(1000):
        sip = f"30.30.10.{random.randint(1, 255)}"
        dip = f"10.10.0.{random.randint(1, 255)}"
        now = float(time.time())
        data3.append([sip, dip, 80, 80, "TCP", "SYN", now, 100])

    ddos.detect_ddos(data3)

    data4 = []
    for x in range(1000):
        if x % 2:
            sip = f"30.30.10.{random.randint(1, 255)}"
            dip = f"10.10.0.{random.randint(1, 255)}"
            now = float(time.time())
        else:
            sip = f"30.30.10.10"
            dip = f"10.10.0.2"
            now = float(time.time())
        data4.append([sip, dip, 80, 80, "TCP", "SYN", now, 100])

    ddos.detect_ddos(data4)
