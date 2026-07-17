import psutil

search = input("Enter process name (Check in task manager): ")

found = False
for proc in psutil.process_iter(['name']):
    try:
        if search.lower() in proc.info['name'].lower():
            print({proc.info['name']})
            found = True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        continue

if not found:
    print("Process not found")