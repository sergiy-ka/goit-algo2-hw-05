import mmh3
import math
import json
import time
import argparse


class HyperLogLog:
    def __init__(self, p=5):
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()
        self.small_range_correction = 5 * self.m / 2 # Поріг для малих значень

    def _get_alpha(self):
        if self.p <= 16:
            return 0.673
        elif self.p == 32:
            return 0.697
        else:
            return 0.7213 / (1 + 1.079 / self.m)

    def add(self, item):
        x = mmh3.hash(str(item), signed=False)
        j = x & (self.m - 1)
        w = x >> self.p
        self.registers[j] = max(self.registers[j], self._rho(w))

    def _rho(self, w):
        return len(bin(w)) - 2 if w > 0 else 32

    def count(self):
        Z = sum(2.0 ** -r for r in self.registers)
        E = self.alpha * self.m * self.m / Z

        if E <= self.small_range_correction:
            V = self.registers.count(0)
            if V > 0:
                return self.m * math.log(self.m / V)

        return E


def load_ip_addresses(file_path):
    ip_addresses = []
    invalid_lines = 0
    total_lines = 0

    with open(file_path, 'r') as file:
        for line in file:
            total_lines += 1
            try:
                # Розбір JSON-даних
                log_entry = json.loads(line.strip())

                # Отримання IP-адреси
                if 'remote_addr' in log_entry and log_entry['remote_addr']:
                    ip_addresses.append(log_entry['remote_addr'])
            except Exception as e:
                invalid_lines += 1
                continue

    print(f"Оброблено {total_lines} рядків, проігноровано {invalid_lines} некоректних рядків")
    return ip_addresses


def exact_count_unique(items):
    return len(set(items))


def approximate_count_unique(items, p=10):
    hll = HyperLogLog(p=p)
    for item in items:
        hll.add(item)
    return hll.count()


def compare_methods(ip_addresses, p=14):
    # Вимірювання часу для точного підрахунку
    start_time = time.time()
    exact_count = exact_count_unique(ip_addresses)
    exact_time = time.time() - start_time

    # Вимірювання часу для наближеного підрахунку
    start_time = time.time()
    approx_count = approximate_count_unique(ip_addresses, p=p)
    approx_time = time.time() - start_time

    # Розрахунок похибки
    error_percent = abs(exact_count - approx_count) / exact_count * 100 if exact_count > 0 else 0

    return {
        'exact_count': exact_count,
        'approx_count': approx_count,
        'exact_time': exact_time,
        'approx_time': approx_time,
        'error_percent': error_percent
    }


def display_results(results):
    print("\nРезультати порівняння:")
    print(f"{'':40} {'Точний підрахунок':<20} {'HyperLogLog':<20}")
    print(f"{'Унікальні елементи':40} {results['exact_count']:<20.1f} {results['approx_count']:<20.1f}")
    print(f"{'Час виконання (сек.)':40} {results['exact_time']:<20.2f} {results['approx_time']:<20.2f}")

    print(f"\nПохибка: {results['error_percent']:.2f}%")


def main():
    """
    Головна функція для запуску порівняння.
    """
    parser = argparse.ArgumentParser(
        description="Порівняння точного та наближеного підрахунку унікальних IP-адрес у лог-файлі.")
    parser.add_argument("file_path", nargs="?", default="lms-stage-access.log",
                        help="Шлях до лог-файлу (за замовчуванням: lms-stage-access.log)")
    parser.add_argument("-p", "--precision", type=int, default=14,
                        help="Параметр точності для HyperLogLog (за замовчуванням: 14)")

    args = parser.parse_args()

    print(f"Завантаження IP-адрес з лог-файлу: {args.file_path}")
    ip_addresses = load_ip_addresses(args.file_path)
    print(f"Завантажено {len(ip_addresses)} IP-адрес")

    print(f"Порівняння методів підрахунку з точністю HyperLogLog p={args.precision}...")
    results = compare_methods(ip_addresses, p=args.precision)

    display_results(results)


if __name__ == "__main__":
    main()