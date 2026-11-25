"""Wait for the public Actions artifact index before deploying Pages."""
import json
import os
import time
from urllib.request import Request, urlopen

url = (os.environ.get('GITHUB_API_URL', 'https://api.github.com')
       + '/repos/' + os.environ['GITHUB_REPOSITORY']
       + '/actions/runs/' + os.environ['GITHUB_RUN_ID'] + '/artifacts')
for attempt in range(20):
    try:
        request = Request(url, headers={'User-Agent': 'ics-vex-pages-publication'})
        with urlopen(request, timeout=10) as response:
            artifacts = json.load(response).get('artifacts', [])
        if any(item['name'] == 'github-pages' and not item['expired'] for item in artifacts):
            print('Pages artifact is available for deployment.')
            break
    except Exception as error:
        print('Artifact index is not ready:', type(error).__name__)
    if attempt == 19:
        raise SystemExit('Pages artifact did not become available within the publication window.')
    time.sleep(3)
