
import time
import argparse
import math

parser = argparse.ArgumentParser()
parser.add_argument("--duration_sec", type=float, required=True)
parser.add_argument("--level", type=int, default=1)
args = parser.parse_args()

t0 = time.time()
junk = 0.0
while (time.time() - t0) < args.duration_sec:
    for i in range(50000 * max(1, args.level)):
        junk += math.sqrt((i % 97) + 1.0)
print(junk)
