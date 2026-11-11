import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

options = Options()
options.add_argument("--headless=new")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.add_argument("--window-size=1920,1080")

driver = webdriver.Chrome(options=options)
try:
    driver.get("http://172.31.105.11:7070/console/")
    time.sleep(2)

    # Set authentication in localStorage
    driver.execute_script("""
        localStorage.setItem('token', 'session-active-token');
        localStorage.setItem('role', 'Platform Admin');
        localStorage.setItem('user', JSON.stringify({username: 'admin'}));
    """)

    # Reload console with token
    driver.get("http://172.31.105.11:7070/console/")
    time.sleep(4)

    # Click on Endpoint Security Posture
    for b in driver.find_elements(By.TAG_NAME, "button"):
        if "Endpoint Security" in b.text:
            b.click()
            print("Clicked Endpoint Security")
            break
    time.sleep(5)

    # Check button text in the screen
    for b in driver.find_elements(By.TAG_NAME, "button"):
        if "Online" in b.text or "Endpoint" in b.text or "Fleet" in b.text:
            print("Button:", b.text.replace("\n", " "))

    # 1. Screenshot of Managed Endpoints (All 2727)
    for b in driver.find_elements(By.TAG_NAME, "button"):
        if "Managed Endpoints" in b.text:
            b.click()
            print("Clicked Managed Endpoints tab")
            break
    time.sleep(3)
    p1 = r"C:\Users\resanul\.gemini\antigravity\brain\57a209ac-5f0d-4594-8d6a-22fdcf002cd8\verify_managed_endpoints_clean.png"
    driver.save_screenshot(p1)
    print("Screenshot 1 saved:", p1)

    # 2. Screenshot of Online Devices tab
    for b in driver.find_elements(By.TAG_NAME, "button"):
        if "Online Devices" in b.text:
            b.click()
            print("Clicked Online Devices tab")
            break
    time.sleep(3)
    p2 = r"C:\Users\resanul\.gemini\antigravity\brain\57a209ac-5f0d-4594-8d6a-22fdcf002cd8\verify_online_devices_clean.png"
    driver.save_screenshot(p2)
    print("Screenshot 2 saved:", p2)

finally:
    driver.quit()
