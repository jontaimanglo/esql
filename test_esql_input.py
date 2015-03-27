#!/usr/bin/python2.7
import uuid
import random
import requests
import datetime
from time import strftime
try:
    import simplejson as json
except:
    import json
from lib.helper import hashString

try:
    requests.delete("http://localhost:9200/_all")
except:
    pass

test1 = { "debug": "on",
    "window": {
        "title": "Sample Konfabulator Widget",
        "name": "main_window",
        "width": 500,
        "height": 500
    },
    "image": { 
        "src": "Images/Sun.png",
        "name": "sun1",
        "hOffset": 250,
        "vOffset": 250,
        "alignment": "center"
    },
    "text": {
        "data": "Click Here",
        "size": 36,
        "style": "bold",
        "name": "text1",
        "hOffset": 250,
        "vOffset": 100,
        "alignment": "center",
        "onMouseUp": "sun1.opacity = (sun1.opacity / 100) * 90;"
    }
}

_out1 = []
for i in range(0, 10):
    temp = {}
    keys = test1.keys()
    random.shuffle(keys)
    _k = keys[random.randint(0, len(keys)-1)]
    new_k = hashString(json.dumps(test1[_k]), "md5")
    temp = dict(test1.items() + {"new_k": new_k}.items())
    _out1.append(temp)

test2 = {
    "new_k": "",
    "uuid": "",
    "tags": [],
    "date_added": ""
}

_out2 = []
for i in range(0, 10):
    temp = {}
    _uuid = str(uuid.uuid4())
    new_k = hashString(_uuid, "md5")
    _date = (datetime.datetime.now() - datetime.timedelta(days=random.randint(1,30))).strftime("%Y-%m-%d")
    temp.update({"new_k": new_k, "uuid": _uuid, "tags": [random.randint(0,10), random.randint(0,10)], "date_added": _date}) 
    _out2.append(temp)

test3 = {
    "new_k": "",
    "info": {
        "name": "",
        "dimensions": []
    },
    "date_added": ""
}

_out3 = []
for i in range(0, 10):
    temp = {}
    _uuid = str(uuid.uuid4())
    new_k = hashString(_uuid, "md5")
    _date = (datetime.datetime.now() - datetime.timedelta(days=random.randint(30, 90))).strftime("%Y-%m-%d")
    temp.update({"new_k": new_k, "info": {"name": _uuid, "dimensions": [random.randint(0,20), random.randint(0,20)]}, "date_added": _date}) 
    _out3.append(temp)

print("[INFO] creating indices")
requests.put("http://localhost:9200/test1")
requests.put("http://localhost:9200/test2")
requests.put("http://localhost:9200/test3")

print("[INFO] creating aliases")
requests.post("http://localhost:9200/_aliases", data=json.dumps({"actions": [{"add": {"index": "test1", "alias": "tst1"}}]}))
requests.post("http://localhost:9200/_aliases", data=json.dumps({"actions": [{"add": {"index": "test2", "alias": "tst2"}}]}))
requests.post("http://localhost:9200/_aliases", data=json.dumps({"actions": [{"add": {"index": "test3", "alias": "tst3"}}]}))

print("[INFO] adding data")
for i, v in enumerate(_out1):
    requests.put("http://localhost:9200/test1/test/%d" % i, data=json.dumps(v))
for i, v in enumerate(_out2):
    requests.put("http://localhost:9200/test2/test/%d" % i, data=json.dumps(v))
for i, v in enumerate(_out3):
    requests.put("http://localhost:9200/test3/test/%d" % i, data=json.dumps(v))
