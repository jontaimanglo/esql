#!/usr/bin/env python
import re
import requests
import hashlib
from collections import OrderedDict
try:
	import simplejson as json
except:
	import json


###
# args: v (string value)
#       doLower (lower cleaned string; default is True)
# purpose: properly clean and lower a string
# returns: the string after processing
# usage:
#       v = cleanAndLower(v)
# references: None
###
def cleanAndLower(v, doLower=True):
        if not v:
                return None
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

###
# args: v (value to check against elasticsearches special characters
#       special (is v a special value; e.g. keyword, default is False)
# purpose: to properly escape elasticsearches special characters
# returns: an escaped string
# usage:
#       escaped_v = escapeESSpecialChars(v)
# references: http://www.elasticsearch.org/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html (reserved characters)
#       + - && || ! ( ) { } [ ] ^ " ~ * ? : \ /
###
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

###
# args: base_url (url path for given request; can be provided as a dict in the format:
#                       {base_url1: req_path, base_url2: req_path}
#               as a list in the format:
#                       [base_url1, base_url2]
#               or as a string:
#                       base_url1
#               )
#       req_path (path to object(s); can be provided as an empty string (if base_url is a
#               dict), or as a list that matches, by index number, to base_urls' list. ex:
#                       [base_url1, base_url2], [req_path_for_base_url1, req_path_for_base_url2]
#               if there is NOT a corresponding req_path at the index number of base_url list,
#               req_path[0] will be used as default; default is None)
#       headers (any header values in dict format; default None)
#       auth (any authentication in appropriate methods; default is empty list; a list of 
#               authentication dicts can be passed. like base_url and req_path lists, a
#               corresponding value based on index number will be used.)
#       cookies (cookie data in dict format; default None)
#       data (post data in dict format; default None; data can be a list of data dicts. like
#               base_url and req_path lists, a corresponding value based on index number
#               will be used.)
#       files (file data to send - will cause a multipart/form-data submission and neither this, nor
#               data will be jsonized prior to submission)
#       method (which method to use other than GET or POST; can be a list)
#       verify (should SSL sites be verified?  Default is True)
#       timeout (server timeout, default is -1; that is, system configured timeout is used)
#       returnErr (if set to True, return error as given by the request)
# purpose: build the proper request format
# returns: json results if successful, text if not, finally None
# usage:
#       results = urlQuery('www.somesite.biz', 'question/path')
# references: None      
###
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

###
# args: s (string to hash)
#       hasher (hash library to use)
# purpose: determines the hash of a string
# returns: hash of the string
# usage:
#       stringhash = hashString("stringtohash")
# references: None
###
def hashString(s, hasher):
        if isinstance(hasher, basestring):
                hasher = hashlib.new(hasher)
        hasher.update(s)
        return hasher.hexdigest()
