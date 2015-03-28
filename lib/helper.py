#!/usr/bin/env python
import re
import requests
import hashlib
from collections import OrderedDict
try:
	import simplejson as json
except:
	import json


def cleanAndLower(v, doLower=True):
        if not v:
                return None
	if isinstance(v, list):
		temp_v = []
		for vv in v:
			temp_v.append(cleanAndLower(vv, doLower=doLower))
		return temp_v
        if not isinstance(v, str):
                v = "%s" % v
        v = v.strip('\r\n')
        v = re.sub('(^\s+|\s+$)', '', v)
        if doLower:
                try:
                        v = v.lower()
                except:
                        pass
        return v

def escapeESSpecialChars(v, special=False, ftype=None):
        es_special_list = ['+', '-', '&&', '||', '!', '(', ')', '{', '}', '[', ']', '^', '~', '*', '?', ':', '/']
        es_special_addl = {}
        if not ftype == "contentType" and not ftype == "content_type":
                es_special_addl["content_type"]  = ['\\', '"']
        try:
                es_special_list = es_special_list + es_special_addl.vals()
        except:
                es_special_list = es_special_list
        for es in es_special_list:
                if not special:
                        v = re.sub(re.escape(es), "\%s" % es, v)
                elif es in ["*"]:
                        continue
        return v

def urlQuery(base_url, req_path=None, headers={}, auth=[], cookies={}, data=None, files=None, method=None, verify=True, timeout=-1, returnErr=True):
        if not req_path:
                req_path = ""
        _base_url = OrderedDict()
        if isinstance(base_url, list) and isinstance(req_path, list):
                for bc, bu in enumerate(base_url):
                        try:
                                _base_url[bu] = req_path[bc]
                        except:
                                _base_url[bu] = req_path[0]
        elif not isinstance(base_url, dict):
                _base_url = {base_url: req_path}
        else:
                _base_url = base_url
        if data:
                if not isinstance(data, list):
                        _data = [data]
                else:
                        _data = data
        else:
                _data = data
        if files:
                if not isinstance(files, list):
                        _files = [files]
                else:
                        _files = files
                if not _data:
                        _data = [data]
        else:
                if _data:
                        _files = [files]
                else:
                        _files = files
        if method:
                if not isinstance(method, list):
                        _method = [method]
                else:
                        _method = method
        else:
                _method = method
        if not isinstance(auth, list):
                auth = [auth]
        if len(auth) == 0:
                auth = {}
        if timeout > 0:
                timeout = float(timeout)
        else:
                timeout = float(c.getConfSection("main")["timeout"])
        _errCode = False
        url_counter = 0
        for base_url, req_path in _base_url.iteritems():
                req_url = base_url
                if not req_path == "":
                        req_url = '%s/%s' %(base_url, req_path)
                try:
                        _auth = auth[url_counter]
                except:
                        _auth = {}
                #print("[DEBUG] base_url:'%s', req_path:'%s', headers:'%s', auth:'%s', cookies:'%s', data: %s, files: %s" %(base_url, req_path, headers, _auth, cookies, _data, _files))
                try:
                        try:
                                if (_data and _data[url_counter]) or (_files and _files[url_counter]):
                                        data = _data[url_counter]
                                        if not (_files and _files[url_counter]):
                                                if isinstance(_data[url_counter], dict):
                                                        try:
                                                                data = json.dumps(_data[url_counter])
                                                        except Exception, err:
                                                                print("[ERROR] Unable to jsonize data: %s" % err)
                                        files = _files[url_counter]
                                        if _method:
                                                if _method[url_counter].lower() == "put":
                                                        try:
                                                                req = requests.put(req_url, headers=headers, auth=_auth, cookies=cookies, verify=verify, data=data, files=files, timeout=timeout)
                                                        except Exception, err:
                                                                print("[ERROR] Unable to send PUT %s: %s" %(req_url, err))
                                                                if returnErr:
                                                                        _errCode = str(err)
                                                                        return {"error": _errCode}
                                                                return False
                                                else:
                                                        print("[ERROR] Unknown method provided '%s'" % _method[url_counter].upper())
                                                        return False
                                        else:
                                                try:
                                                        req = requests.post(req_url, headers=headers, auth=_auth, cookies=cookies, verify=verify, data=data, files=files, timeout=timeout)
                                                except Exception, err:
                                                        print("[ERROR] Unable to send POST %s: %s" %(req_url, err))
                                                        if returnErr:
                                                                _errCode = str(err)
                                                                return {"error": _errCode}
                                                        return False
                                else:
                                        raise Exception("No data found, possibly GET request")
                        except Exception, err:
                                #print("[DEBUG] Error connecting to url with data and/or file provided: %s" % err)
                                if re.search("Timeout", str(err)):
                                        print("[WARN] Timeout: %s, %s" %(err, req.status_code))
                                else:
                                        if _method:
                                                if _method[url_counter].lower() == "delete":
                                                        req = requests.delete(req_url, headers=headers, auth=_auth, cookies=cookies, verify=verify, timeout=timeout)
                                                else:
                                                        print("[ERROR] Invalid method '%s' provided" % _method[url_counter])
                                                        return False
                                        else:
                                                req = requests.get(req_url, headers=headers, auth=_auth, cookies=cookies, verify=verify, timeout=timeout)
                        if req.status_code >= 400:
                                print("[WARN] Failed to connect to '%s': %s, %s" %(req_url, req.status_code, req.text))
                                #print("[DEBUG] [url_counter] %s, len(_base_url): %s" %(url_counter, len(_base_url)))
                                if url_counter  == len(_base_url):
                                        print("[ERROR] All urls provided failed")
                                        if returnErr:
                                                _errCode = str(req.text)
                                                return {"error": _errCode}
                                        return False
                                if returnErr:
                                        _errCode = str(req.text)
                                #print("[DEBUG] Checking next url")
                                url_counter += 1
                                continue
                        try:
                                return req.json()
                        except Exception, err:
                                #print("[DEBUG] json not available: %s" % err)
                                return req.text
                        except:
                                #print("[DEBUG] text not available")
                                return True
                except Exception, err:
                        print("[WARN] Failed to obtain request '%s': %s" %(req_url, err))
                        if url_counter < len(_base_url):
                                print("[DEBUG] Checking next url")
                                url_counter += 1
                                continue
                print("[ERROR] All urls provided failed")
                return False
        if returnErr and _errCode:
                return {"error": _errCode}
        return False

def hashString(s, hasher):
        if isinstance(hasher, basestring):
                hasher = hashlib.new(hasher)
        hasher.update(s)
        return hasher.hexdigest()
