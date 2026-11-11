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

    # Click on "Top Notable Events" tab button
    for b in driver.find_elements(By.TAG_NAME, "button"):
        if "Top Notable Events" in b.text:
            b.click()
            print("Clicked Top Notable Events tab button")
            break
    time.sleep(3)

    # Save screenshot
    p = r"C:\Users\resanul\.gemini\antigravity\brain\57a209ac-5f0d-4594-8d6a-22fdcf002cd8\verify_notables_timestamp_added.png"
    driver.save_screenshot(p)
    print("Screenshot saved to:", p)

    # Check the headers in the notables table
    headers = [th.text for th in driver.find_elements(By.TAG_NAME, "th")]
    print("Headers:", headers)

finally:
    driver.quit()
