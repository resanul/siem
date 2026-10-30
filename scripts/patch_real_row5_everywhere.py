import re

with open('frontend/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace in initial state
content = content.replace('monitoredAssets: 3452,', 'monitoredAssets: 11,')
content = content.replace('ingestedData: "2.4 TB",', 'ingestedData: "40.2 GB",')
content = content.replace('activeUsers: 8921,', 'activeUsers: 12,')

# mitre in initial state
content = re.sub(r'mitreCoverage:\s*158(\s*\n\s*\};)', r'mitreCoverage: 31\1', content)

# Replace in second fetchOverview
content = content.replace('monitoredAssets: dataOverview.metrics.monitored_assets || 3452,', 'monitoredAssets: dataOverview.metrics.monitored_assets !== undefined ? dataOverview.metrics.monitored_assets : 11,')
content = content.replace('ingestedData: dataOverview.metrics.ingested_data || "2.4 TB",', 'ingestedData: dataOverview.metrics.ingested_data || "40.2 GB",')
content = content.replace('activeUsers: dataOverview.metrics.active_users || 8921', 'activeUsers: dataOverview.metrics.active_users !== undefined ? dataOverview.metrics.active_users : 12')

with open('frontend/index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print('Updated successfully')
