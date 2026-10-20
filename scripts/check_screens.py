with open(r'frontend\index.html', 'r', encoding='utf-8') as f:
    text = f.read()

sidebar_ids = [
    'overview', 'alerts', 'search', 'hosts', 'network', 'cases',
    'adversary_sim', 'bas_testing', 'purple_team', 'soar_playbooks',
    'threat_hunting', 'mitre_heatmap', 'threat_intel', 'sigma_studio',
    'rules', 'reports', 'inventory', 'jobs', 'health', 'releases', 'backup',
    'audit', 'settings'
]

print("=== SIDEBAR SCREEN RENDER CHECK ===")
for sid in sidebar_ids:
    has_render = f'currentScreen === "{sid}"' in text or f"currentScreen === '{sid}'" in text
    print(f"{sid:20}: {'FOUND' if has_render else 'MISSING !!!'}")
