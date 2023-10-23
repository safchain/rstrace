import subprocess
import time

print("webapp started")

while True:
    print("activity")
    subprocess.run(["host", "perdu.com"])
    time.sleep(5)

