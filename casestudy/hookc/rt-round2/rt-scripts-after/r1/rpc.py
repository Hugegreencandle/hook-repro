import json, sys, urllib.request
def rpc(url, method, params):
    req = urllib.request.Request(url, data=json.dumps({"method": method, "params": [params]}).encode(),
                                 headers={"content-type": "application/json", "user-agent": "rt-readonly"})
    return json.loads(urllib.request.urlopen(req, timeout=60).read())["result"]
