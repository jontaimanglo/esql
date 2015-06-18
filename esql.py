#!/usr/bin/env python
import re
import argparse
import collections
from requests.auth import HTTPBasicAuth
try:
	import simplejson as json
except:
	import json
#local libraries
from lib.helper import cleanAndLower, escapeESSpecialChars, urlQuery, hashString

###
'''
	Provides SQL like notation commands to elasticsearch dsl query syntax conversion.
	Currently supports:
		commands:	SELECT, SHOW
		clauses:	FROM, WHERE, LIMIT, OFFSET
		operands:	AND, OR, NOT
		comparisons:	=, <, <=, >=, >, LIKE
		sorting:	ORDER BY <FIELD> (DESC|ASC)
		ranges:		BETWEEN
		misc:		EXPLAIN, DISTINCT(<FIELD>(,<FIELD)), COUNT(<FIELD>)
		
	Examples:
		SHOW TABLES
		SHOW COLUMNS FROM <TABLE>
		SELECT * FROM <TABLE>
		SELECT <FIELD1>, <FIELD2> FROM <TABLE> WHERE <FIELD1>=<VALUE> AND <FIELD2>=<VALUE> BETWEEN <DATE1> AND <DATE2>
		SELECT * FROM <TABLE> ORDER BY <FIELD> LIMIT <INT> OFFSET <INT>
		SELECT * FROM <TABLE> WHERE <FIELD> LIKE <REGEXP> LIMIT <INT>
		SELECT field1 FROM <TABLE> WHERE COUNT(field2) >= <INT>
		SELECT DISTINCT(field) FROM <TABLE> WHERE COUNT(field) <= <INT>
		SELECT DISTINCT(field1, field2), field3 FROM <TABLE> LIMIT <INT>
		SELECT COUNT(field) FROM <TABLE> WHERE COUNT(field) > <INT>
		SELECT COUNT(DISTINCT(field)) FROM <TABLE>
		EXPLAIN SELECT COUNT(field) FROM <TABLE>

http://www.elasticsearch.org/blog/all-about-elasticsearch-filter-bitsets/
When composing filters, geo/script/numeric_range should all use and/or/not; otherwise, bool.
ex.
{
    "and": [
        {
            "bool": {
                "must": [
                    {
                        "term": {}
                    },
                    {
                        "range": {}
                    },
                    {
                        "term": {}
                    }
                ]
            }
        },
        {
            "custom_script": {}
        },
        {
            "geo_distance": {}
        }
    ]
}
'''
###
DEFAULT_BOOL = "must"
DEFAULT_OP = "and"
OP_MAP = {"and": "must", "or": "should", "not": "must_not"}

class esql:
	def __init__(self, debug=False):
                #we have es hosts behind a nginx proxy, so we require a user and password; set to None if not applicable
                self.es_conf = {"hosts": ["http://localhost"], "port": 9200, "delimiter": ".", "timeout": 120.0, "user": None, "password": None}
                #need to know the field to use when using BETWEEN
                self.es_conf["date_mapping"] = {"tst2": "date_added", "tst3": "date_added"}
                self.es_hosts = []
                for h in self.es_conf['hosts']:
                        self.es_hosts.append("%s:%s" %(h, self.es_conf['port']))
                self.timeout = 120.0
                try:
                        self.delimiter = self.es_conf["delimiter"]
                except:
                        self.delimiter = "."
		self.DEBUG = debug
		print("[DEBUG] DEBUG is set to: %s" % self.DEBUG)
	
	def query(self, q):
		if re.search("help", q, re.IGNORECASE):
			return self._help()
		q, t = self._parseQuery(q)
		if not q:
			print("[INFO] No results found")
			return {}
		if not t:
			return {'warn': 'unable to determine query type'}
		try:
			if "error" in q.values()[0].keys():
				return q.values()[0]
		except:
			pass
		final_q, final_d = self._formatQuery(q)
		explain = {}
		if t == "explain":
			explain = {"explain": {"api": final_q, "dsl": final_d}}	
		if self.DEBUG:
			print("[DEBUG] %s, %s" %(final_q, json.dumps(final_d, indent=4)))
		try:
			es_results = urlQuery(self.es_hosts, [final_q], auth=HTTPBasicAuth(self.es_conf['user'], self.es_conf['password']), data=[final_d], verify=False, timeout=self.timeout, returnErr=True)
		except Exception, err:
			return {'error': "%s" % err}
		if not es_results or (es_results and len(es_results) == 0):
			return {'info': 'no results found'}
		try:
			es_results = es_results["error"]
		except:
			es_results = self._formatResults(es_results, t)
		try:
			_esr = es_results.copy()
			_esr.update(explain)
			es_results = _esr
		except:
			pass
		return es_results

	def _help(self):
		_h = {}
		_h["commands"] = ["SELECT", "SHOW"]
		_h["clauses"] = ["FROM", "WHERE", "LIMIT", "OFFSET"]
		_h["operands"] = ["AND", "OR", "NOT"]
		_h["comparisons"] = ["=", "<", "<=", ">=", ">", "LIKE"]
		_h["sorting"] = ["ORDER BY <FIELD> (DESC|ASC)"]
		_h["ranges"] = ["BETWEEN"]
		_h["misc"] = ["EXPLAIN", "DISTINCT(<FIELD>(,<FIELD))", "COUNT(<FIELD>)"]
		return _h

	def _parseQuery(self, q):
		index = self._findIndex(q)
		if not index:
			return {'error': 'unable to determine index from statement; syntax: SELECT * FROM <TABLE>'}
		parsedq = {index: []}
		t = None
		if re.search("show", q, re.IGNORECASE):
			parsedq[index] = self._show(q)
			t = "show"
		elif re.search("select", q, re.IGNORECASE):
			self.total_count = False
			self.distinct = None
			mapping = {}
			_mapping = self.query("SHOW COLUMNS FROM %s" % index)
			try:
				mapping = self._flattenMapping(_mapping.values()[0])
			except Exception, err:
				print("[WARN] Unable to parse and/or flatten mapping for index '%s': %s" %(index, err))
			if re.search("explain", q, re.IGNORECASE):
				q = re.sub("^(\s+)?explain", "", q, 1, re.IGNORECASE)
				t = "explain"
			elif re.search("select", q, re.IGNORECASE):
				t = "select"
			parsedq[index] = self._select(q, index, mapping)
		return parsedq, t

	def _formatQuery(self, q):
		if not isinstance(q, dict):
			print("[ERROR] Invalid format provided (%s)" % repr(q))
			return None
		dsl = None
		data = None
		for qk, qv in q.iteritems():
			if isinstance(qk, int) or re.search("true|false", qk, re.IGNORECASE):
				qqk = '/' . join(qv.keys())
				qqv = '/' . join(qv.values())
				dsl = "%s/%s" %(qqk, qqv)
			elif isinstance(qv, dict):
				if len(qv) > 0:
					for qqk, qqv in qv.iteritems():
						if not qqv:
							dsl = "%s/%s" %(qk, qqk)
						else:
							if self.total_count and not self.distinct:
								dsl = "%s/_count?ignore_unavailable=True" % qk
							else:
								dsl = "%s/_search?ignore_unavailable=True" % qk
							if not isinstance(data, dict):
								data = {}
							data.update({qqk: qqv})	
				else:
					if self.total_count and not self.distinct:
						dsl = "%s/_count" % qk
					else:
						dsl = "%s/_search" % qk
		return dsl, data

	def _formatResults(self, results, t):
		res = {}
		if t == "show":
			for rk, rv in results.iteritems():
				try:
					idx = '' . join(rv["aliases"].keys())
					try:
						res[idx]
					except:
						res[idx] = 1
				except:
					idx = rv["mappings"].keys()[0]
					_temp_res = rv["mappings"].values()[0]
					try:
						res[idx].update(_temp_res["properties"])
					except:
						res[idx] = _temp_res["properties"]
		elif t == "select" or t == "explain":
			_distinct = {}
			if self.total_count and not self.distinct:
				return {"count": results["count"]}
			for rk in results["hits"]["hits"]:
				try:
					if self._findDistinct(rk["_source"]):
						res[rk["_id"]] = rk["_source"]
				except:
					try:
						if self._findDistinct(rk["fields"]):
							res[rk["_id"]] = rk["fields"]
					except Exception, err:
						print("[ERROR] Unable to extract _source or fields from results: %s" % err)
						res["error"] = "unable to extract data from results"
			if self.total_count:
				try:
					res["error"]
				except:
					return {"count": len(res)}
		return res

	def _findDistinct(self, res):
		if not self.distinct:
			return True
		values = ""
		try:
			for k in self.distinct.keys():
				f = json.dumps(res[k])
				values = "%s%s" %(values, f)
			values = hashString(values, "md5")
			try:
				self._distinct[values]
				return False
			except:
				self._distinct.update({values: 1})
		except:
			pass
		return True

	def _findIndex(self, q):
		index = True
		if re.search("from", q, re.IGNORECASE):
			_q = re.split(" from ", q, 1, flags=re.IGNORECASE)
			try:
				_index = _q[1]
				index = '' . join(re.split("(where|order|limit|between)", _index, 1, flags=re.IGNORECASE)[0])
 			except Exception, err:
				index = None
				print("[ERROR] Unable to determine index from statement '%s': %s" %(q, err))
		return cleanAndLower(index, doLower=False)

	def _flattenMapping(self, mapping, pkey=""):
		items = []
		for k, v in mapping.items():
			if not k in ["type", "format", "properties"]:
				new_key = pkey + self.delimiter + k if pkey else k
			else:
				new_key = pkey
			if isinstance(v, collections.MutableMapping):
				items.extend(self._flattenMapping(v, new_key).items())
			else:
				items.append((new_key, v))
		return dict(items)

	def _select(self, origq, index, mapping):
		q = {}
		temp_q = {}
		qkeys = []
		qvals = []
		columns = re.search("select (.*) from", origq, re.IGNORECASE)
		if columns:
			try:
				_fields = columns.group(1)
				_fields = re.sub("(\s+)?,(\s+)?", ",", _fields)
				_total_count = re.search("count(.+)", _fields, re.IGNORECASE)
				if _total_count:
					try:
						total_count = _total_count.group(1).strip("()")
						self.total_count = True
					except Exception, err:
						if re.search("count", columns, re.IGNORECASE):
							print("[ERROR] Unable to extract count from '%s': %s" %(repr(origq), err))
							return {"error": "unable to extract count fields"}
					_fields = total_count
					qkeys.append("count")
					qvals.append("*")
				distinct = re.search("distinct([^)]+)", _fields, re.IGNORECASE)
				if distinct:
					try:
						non_distinct = re.split(re.escape(str(distinct.group(1))), _fields, re.IGNORECASE)[1]
						non_distinct = re.sub("\(|\)", "", non_distinct)
						_non_distinct = non_distinct.split(",")
						non_distinct = [n for n in _non_distinct if not n == ""]
					except Exception, err:
						non_distinct = []
					try:
						_distinct = re.sub("distinct|\(|\)", "", str(distinct.group(1)), flags=re.IGNORECASE)
						distinct = _distinct.split(",")
					except Exception, err:
						if re.search("distinct", origq, re.IGNORECASE):
							print("[ERROR] Unable to extract distinct from '%s': %s" %(repr(origq), err))
							return {"error": "unable to extract distinct field(s)"}
					_fields = ',' . join(distinct + non_distinct)
					self.distinct = {d: 1 for d in distinct}
					qkeys.append("distinct")
					qvals.append(_distinct)
				fields =[cleanAndLower(f, doLower=False) for f in _fields.split(",")]
				if (self.total_count and self.distinct) or not self.total_count:
					q.update({"_source": fields})
			except Exception, err:
				print("[ERROR] Unable to extract select columns from '%s': %s" % (repr(origq), err))
				return {'error': 'unable to extract select clause'} 	
			origq = '' . join(re.split("from", origq, 1, flags=re.IGNORECASE)[1:])
		offset = re.search("offset [0-9]{1,}", origq, re.IGNORECASE)
		if offset:
			try:
				_offset = offset.group(0)
				offset = '' . join(re.split("offset", _offset, 1, flags=re.IGNORECASE)[1])
				offset = cleanAndLower(offset, doLower=False)
				q.update({"from": int(offset)})
			except Exception, err:
				if re.search("offset", origq, re.INGORECASE):
					print("[ERROR] Unable to extract offset from '%s': %s" %(repr(origq), err))
					return {'error': 'unable to extract offset clause'}
			origq = '' . join(re.split("offset", origq, 1, flags=re.IGNORECASE)[0])
		limit = re.search("limit [0-9]{1,}", origq, re.IGNORECASE)
		if limit:
			try:
				_limit = limit.group(0)
				limit = '' . join(re.split("limit", _limit, 1, flags=re.IGNORECASE)[1])
				limit = cleanAndLower(limit, doLower=False)
				#size argument is not supported when using
				if (self.total_count and self.distinct) or not self.total_count:
					q.update({"size": int(limit)})
			except Exception, err:
				if re.search("limit", origq, re.INGORECASE):
					print("[ERROR] Unable to extract limit from '%s': %s" %(repr(origq), err))
					return {'error': 'unable to extract limit clause'}
			origq = '' . join(re.split("limit", origq, 1, flags=re.IGNORECASE)[0])
		order = re.search("order by (.*) (desc|asc)", origq, re.IGNORECASE)
		if order:
			try:
				_order = order.group(0)
				temp_order = re.split("order by", origq, 1, flags=re.IGNORECASE)
				order_values = re.split("(desc|asc)", '' . join(temp_order[1:]), 1, flags=re.IGNORECASE)
				direction = order_values[1]
				_sort_values = order_values[0].split(",")
				sort_values = [cleanAndLower(s, doLower=False) for s in _sort_values]
				q.update({"sort": [{k: {"order": direction.lower()} for k in sort_values}]})
			except Exception, err:
				if re.search("order by", origq, re.IGNORECASE):
					print("[ERROR] Unable to extract order by '%s': %s" %(repr(origq), err))
					return {'error': 'unable to extract order clause'}
			origq = '' . join(temp_order[0])
		between = re.search("between (.*) and (.*)", origq, re.IGNORECASE)
		if between:
			q.update({"query": {"filtered": {}}})
			try:
				_between = between.group(0)
				temp_between = re.split("between", origq, 1, flags=re.IGNORECASE)
				_ranges = re.split("and", '' . join(temp_between[1:]), 1, flags=re.IGNORECASE)
				ranges = [cleanAndLower(r, doLower=False) for r in _ranges]
				if ranges[0] > ranges[1]:
					temp_range = ranges[0]
					ranges[0] = ranges[1]
					ranges[1] = temp_range
				es_date_mapping = self.es_conf['date_mapping'][index]
				temp_q.update({"must": {"range": {es_date_mapping: {"gte": ranges[0], "lte": ranges[1]}}}})
				qkeys = qkeys + ["range_gte", "range_lte"]
				qvals = qvals + [ranges[0], ranges[1]]
			except Exception, err:
				if re.search("between", origq, re.IGNORECASE):
					print("[ERROR] Unable to extract between '%s': %s" %(repr(origq), err))
					return {'error': 'unable to extract between clause'}
			origq = '' . join(temp_between[0]) 
		where = re.search("where (.*)", origq, re.IGNORECASE)
		if where:
			temp_origq = []
			op_rgx = re.compile("(\s+)?(<(=)?|>(=)?|=)(\s+)?|[^<>=]+")
			op_iter = op_rgx.finditer(origq)
			for op_match in op_iter:
        			op_m = cleanAndLower(op_match.group(), doLower=False)
        			temp_origq.append(op_m)
			if len(temp_origq) > 0:
				origq = '' . join(temp_origq)
			origq = re.sub("(\s+)?\((\s+)?", " ( ", origq)
			origq = re.sub("(\s+)?\)(\s+)?", " ) ", origq)
			origq = re.sub("(\s+)? like (\s+)?", " like ", origq, flags=re.IGNORECASE)
			try:
				q["query"]["filtered"]
			except:
				q.update({"query": {"filtered": {}}})
			try:
				_condition = where.group(0)
				_temp_condition = re.split("where", origq, 1, flags=re.IGNORECASE)[1]
				temp_condition = []
				split_rgx = re.compile("\w+[=<>]+\"([^\"]*)\"|\w+[=<>]+'([^']*)'|[^\\s\"']+|\"([^\"]*)\"|'([^']*)'")
				split_iter = split_rgx.finditer('' . join(_temp_condition))
				for split_match in split_iter:
					temp_condition.append(split_match.group())
				temp_condition = self._fixConditions(temp_condition)
				temp_condition = self._prepareForDSL(temp_condition)
				where_dsl, qk, qv = self._buildDSL(temp_condition, mapping, temp_q)
				if len(where_dsl) == 0:
					raise Exception("no where clause extracted")
				q["query"]["filtered"].update({"filter": where_dsl})
				q["query"]["filtered"].update({"query": { "match_all": {}}})
				qkeys = qkeys + qk
				qvals = qvals + qv
				temp_q = False
				if self.DEBUG:
					print json.dumps(q, indent=4)
			except Exception, err:
				if re.search("where", origq, re.IGNORECASE):
					print("[ERROR] Unable to extract where from '%s': %s" %(repr(origq), err))
					return {'error': 'unable to extract where clause'}
		try:
			if q["_source"][0] == "*":
				del q["_source"]
		except:
			pass
		if temp_q:
			q["query"]["filtered"].update({"filter": {"bool": temp_q}})
		if len(qkeys) > 0:
			if self.DEBUG:
				print("[qkeys] %s" % qkeys)
				print("[qvals] %s" % qvals)
		return q
	
	def _buildDSL(self, q, mapping, tq=None):
		_build, opchain, lop, lvl = self._buildPrecedence(q)
		build = self._ensurePrep(_build)
                b, op, qk, qv = self._prepare(build, mapping)
                try:
                        b["bool"]["must"]
                except:
                        _b = {}
                        _b.update({"bool": {"must": [b]}})
                        b = {}
                        b = _b
                #tq may contain BETWEEN clause, let's insert that as the first filter
                if tq:
                        try:
                                b["bool"]["must"].insert(0, tq["must"])
                        except:
                                ntq = {}
                                for tk, tv in tq.iteritems():
                                        if not isinstance(tv, list):
                                                ntq[tk] = [tv]
                                b["bool"]["must"].update(ntq)
                return b, qk, qv

	def _expandInner(self, t, last_op):
        	built = {}
		last_op = OP_MAP[last_op]
        	if isinstance(t, list):
                	temp = []
                	for tt in t:
                	        if tt.lower() in ["and", "or", "not"]:
                        	        last_op = OP_MAP[tt.lower()]
                                	if len(temp) == 0:
                                	        continue
                                	try:
                                        	built[last_op].append(temp)
	                                except:
        	                                built.update({last_op: [temp]})
                	                temp = []
                        	else:
                                	temp.append(tt)
	        if len(temp) > 0:
        	        try:
                	        built[last_op].append(temp)
	                except:
        	                built.update({last_op: [temp]})
        	return built

	def _ensurePrep(self, q, new_q=None):
        	if not new_q:
        	        new_q = {}
        	if isinstance(q, dict):
        	        for k, v in q.iteritems():
				temp_q = self._ensurePrep(v, new_q)
				if len(temp_q) == 0:
					continue
				try:
					temp_q[k]
					new_q = temp_q
				except:
                	        	new_q.update({k: temp_q})
        		return new_q
        	elif isinstance(q, list):
                	final_q = []
	                for qq in q:
        	                if isinstance(qq, list):
                	                if not self._checkForInnerList(qq):
                        	                temp_q = []
                                	        for qqq in qq:
                                        	        if not qqq.lower() in ["and", "or", "not"]:
                                                	        temp_q.append(qqq)
	                                                else:
        	                                                final_q.append(temp_q[::])
                	                                        temp_q = []
                        	                if len(temp_q) > 0:
                                	                final_q.append(temp_q[::])
                                        	if len(final_q) == 0:
                                                	final_q = qq
	                                else:
						temp_q = self._ensurePrep(qq, new_q)
						if len(temp_q) == 0:
							continue
        	                                final_q = temp_q #self._ensurePrep(qq, new_q)
                	        elif isinstance(qq, dict):
                        	        for qk, qv in qq.iteritems():
						temp_q = self._ensurePrep(qv, new_q)
						if len(temp_q) == 0:
							continue
                                	        final_q.append({qk: temp_q}) #self._ensurePrep(qv, new_q)})
	                return final_q

	def _checkForInnerList(self, ll):
        	for l in ll:
                	if isinstance(l, list):
				return True
        	return False

	def _addToDict(self, built, inner):
		for k in inner.keys():
			try:
				if isinstance(built[k], dict):
					temp_built = dict(built[k].items() + {k: inner[k]}.items())
					built = temp_built
				elif isinstance(built[k], list):
					for i in inner[k]:
						built[k].append(i)	
				else:
					print("[WARN] Unable to add to dict; neither a dict or a list (%s): %s" %(type(built[k]), built[k]))
			except:
				built.update({k: inner[k]})
		return built

	def _addLevel(self, built, t, opchain, apd_op, prp_op, clvl, flvl, tbuilt=None):
        	if not tbuilt:
        	        tbuilt = {}
        	try:
        	        op = opchain[0]
        	except:
        	        op = "and"
		_op = OP_MAP[op]
        	mod = False
		if clvl == flvl:
			if prp_op:
				op = prp_op
				_op = OP_MAP[prp_op]
                	if isinstance(built, dict):
				inner = self._expandInner(t, op)
                        	try:
                                	if isinstance(built[_op], dict):
						built[_op] = self._addToDict(built[_op], inner)
                                	elif isinstance(built[_op], list):
                                       		built[_op].append(inner)
                        	except Exception, err:
                                	built.update({_op: inner})
	                elif isinstance(built, list):
 				inner = self._expandInner(t, op)
                        	_temp_built = built
                        	_d = None
                        	found = False
                        	for i, b in enumerate(built):
                                	if isinstance(b, dict):
                                        	bkey = b.keys()[0]
	                                        if bkey == _op:
        	                                        built[i][_op].append(inner)
                	                                found = True
                        	                        if apd_op:
                                	                        built[i][_op].append({apd_op: []})
                                        	else:
                                                	if len(built[i][bkey]) <= 1:
                                                        	_d = {i: bkey}
	                        if not found:
        	                        if not _d:
                	                        built.append({_op: [inner]})
                        	        else:
                                	        temp = built[_d.keys()[0]][_d.values()[0]][0]
	                                        built[_d.keys()[0]] = {_op: [temp, inner]}
        	                        if apd_op:
                	                        built[len(built)-1][_op].append({apd_op: []})
                	return built, mod
	        else:
        	        try:
                	        _b = built[_op]
	                except:
        	                _b = built
	                res, mod = self._addLevel(_b, t, opchain[clvl::], apd_op, prp_op, clvl+1, flvl, tbuilt)
                	try:
                                try:
                                        tbuilt[_op].update(res)
                                except:
                                       	tbuilt.update({_op: res})
                	except:
                        	try:
                                	tbuilt[_op].update(res)
                        	except:
                                	tbuilt.update({_op: res})
        	return tbuilt, mod

	def _buildPrecedence(self, temp_conditions, built=None, opchain=None, last_op=None, lvl=0):
        	if not built:
                	built = {}
	        if not opchain or lvl == 0:
        	        opchain = []
	        op = None
        	for t in temp_conditions:
                	if not self._checkForInnerList(t):
	                        prp_op = None
				apd_op = None
        	                skip = False
                	        if len(t) == 1:
                        	        if t[0].lower() in ["and", "or", "not"]:
                                	        op = t[0].lower()
                                        	last_op = op
        	                                skip = True
                	        else:
                        	        if t[0].lower() in ["and", "or", "not"]:
                                	        prp_op = t[0].lower()
						t.pop(0)
        	                        if t[len(t)-1].lower() in ["and", "or", "not"]:
                	                        apd_op = t[len(t)-1].lower()
						t.pop(len(t)-1)
	                        if not op:
                	                if not last_op:
                        	                op = "and"
                                	else:
                                        	op = last_op
        	                opchain.insert(0, op)
                	        if skip:
                        	        continue
	                        built, rop = self._addLevel(built, t, opchain, apd_op, prp_op, 0, lvl)
                	        if rop:
                                	try:
                                        	opchain[lvl]
	                                        del opchain[0]
        	                                opchain[lvl] = op
                	                except:
                        	                pass
	                else:
        	                built, opchain, last_op, lvl = self._buildPrecedence(t, built, opchain, last_op=last_op, lvl=lvl+1)
                	        last_op = None
	        lvl -= 1
        	return built, opchain, last_op, lvl

	def _prepareForDSL(self, temp_conditions):
		prn = 0
		temp = []
		final = []
		for t in temp_conditions:
        		t = cleanAndLower(t, doLower=False)
        		if re.search("^(\(|\))$", t):
                		if len(temp) > 0:
                        		for p in range(0, prn):
                                		temp = [temp]
		                        final.append(temp)
        		                temp = []
                		if t == "(":
                        		prn += 1
		                elif t == ")":
                		        prn -= 1
                		continue
        		temp.append(t)
		if len(temp) > 0:
			for p in range(0, prn):
				temp = [temp]
			final.append(temp)
		return final

	# used to combine count() clauses that may be in different positions in the list provided;
	#	further, if a query is provided with parens around a single clause:
	#	e.g. (foo LIKE bar), these will be removed as they are unneeded.  Each clause in 
	#	a pair+ of parens will require at least a AND/OR/NOT	
	def _fixConditions(self, temp_conditions):
		n = []
		temp = []
		skip = -1
		op_found = False
		op_trigger = False
		op_count = 0
		for i, t in enumerate(temp_conditions):
			if i == skip:
				continue
        		if re.search("\(|\)", t):
                		if t == "(":
					op_count -= 1
                        		try:
                                		if re.search("count", n[i-1], re.IGNORECASE):
                                        		del n[i-1]
                                        		temp = ["count", "("]
						else:
							raise Exception("no exception")
                        		except Exception, err:
						n.append(t)
                         		       	pass
					op_trigger = True
                		if t == ")":
					op_count += 1
					if len(temp) > 0:
                   		     		temp.extend([t, temp_conditions[i+1]])
                        			n.append('' . join(temp))
						skip = i + 1
					else:
						if not op_found:
							for z, tt in enumerate(reversed(temp_conditions[0:i])):
								if tt == "(":
									del n[len(n) - 1 - z]
									break
						else:
							n.append(t)
					if op_count == 0:
						op_found = False
						op_trigger = False
                        		temp = []
                       		continue
			if op_trigger:
				try:
					if t.lower() in OP_MAP.keys():
						op_found = True
				except:
					pass
        		if len(temp) > 0:
                		temp.append(t)
        		else:
                		n.append(t)
		return n

	def _prepare(self, build, mapping, op=DEFAULT_BOOL, new_build=None, qkeys=None, qvals=None):
		if not qkeys:
			qkeys = []
		if not qvals:
			qvals = []
		if isinstance(build, dict):
			for k, v in build.iteritems():
				prep, op, qk, qv = self._prepare(v, mapping, op=k, qkeys=qkeys, qvals=qvals)
				qkeys = qkeys + qk
				qvals = qvals + qv
				try:
					new_build["bool"][op] = prep
				except:
					try:
						new_build["bool"].update({op: prep})
					except:
						try:
							new_build.update({"bool": {op: prep}})
						except:
							try:
								new_build = {"bool": {op: prep}}
							except Exception, err:
								print("[ERROR] Unable to prepare build correctly: %s" % err)
								continue
		if not new_build:
			new_build = []
		_op = op 
		orig_op = op
		if isinstance(build, list):
			formatted = []
			for i, b in enumerate(build):
				if isinstance(b, list):
					try:
						if "like" in (sk.lower() for sk in b):
							formatted, _op, qk, qv = self._formatLike(b, mapping, op, build=formatted)
						elif re.search("^count\([^\)]+\)", b[0], re.IGNORECASE):
							formatted, _op, qk, qv = self._formatCount(b, mapping, op)
						else:
							formatted, _op, qk, qv = self._formatDefault(b, mapping, op)
						if _op != op and _op != orig_op:
							op = _op
						try:
							if formatted[1]:
								for z, n in enumerate(new_build):
									if hashString(json.dumps(n), "md5") == hashString(json.dumps(formatted[1]), "md5"):
										del new_build[z]
										break
						except Exception, err:
							pass
						qkeys.append(qk)
						qvals.append(qv)
						new_build.append(formatted[0])
					except Exception, err:
						print("[WARN] Expected list, observed '%s' for (%s): %s" %(type(b), repr(b), err))
						continue
				elif isinstance(b, dict):
					for k, v in b.iteritems():
						prep, op, qk, qv = self._prepare(v, mapping, op=k, qkeys=qkeys, qvals=qvals)
						qkeys = qkeys + qk
						qvals = qvals + qv
						try:
							new_build[0]["bool"][op].extend(prep)
						except:
							try:
								new_build[0]["bool"].update({op: prep})
							except:
								new_build.append({"bool": {op: prep}})
						op = orig_op
		return new_build, op, qkeys, qvals
 
	def _formatDSL(self, field, mapping_path, op=DEFAULT_BOOL, build=None):
		if not build:
			build = {}
		try:
			build = build[0]
		except:
			build = {}
		updated = False
		if not mapping_path == "_DEFAULT_":
			try:
				e_path = build["nested"]["path"]
				if e_path == mapping_path:
					updated = {"nested": build["nested"]}
					try:
						build["nested"]["filter"]["bool"][op].append(field)
					except Exception, err:
						build["nested"]["filter"]["bool"].update({op: [field]})
				else:
					raise Exception("different paths")
			except Exception, err:
				build = {"nested": {"path": mapping_path, "filter": {"bool": {op: [field]}}}}
		else:
			#adhere to bitset guidance
			if field.keys()[0] in ["script", "geo_distance"]:
				build = {op: [field]}
			else:
				build = field
		return [build, updated]	

	def _formatLike(self, fields, mapping, op=DEFAULT_BOOL, build=None):
		fields = cleanAndLower(fields, doLower=False)
		_regexp = {"regexp": {fields[0]: {"value": re.sub("^('|\")|('|\")$", "", fields[2]), "flags": "NONE"}}}
		mapping_path = self._mapping_match(mapping, fields[0])
		return self._formatDSL(_regexp, mapping_path, op=op, build=build), op, self._buildQKeys(op, fields[0], "_~"), fields[2]

	def _formatCount(self, fields, mapping, op=DEFAULT_BOOL):
		op_map = {"and": "must", "or": "should", "not": "must_not"}
		if isinstance(fields, list):
			fields = fields[0]
		_op = op
		for k, v in op_map.iteritems():
			if v == op.lower():
				_op = k
				break
		count = re.sub("count|\(|\)", "", fields, flags=re.IGNORECASE)
		mapping_path = self._mapping_match(mapping, count)
		_count, _tc, _qk = self._parseQFields(count, pq="count")
		return self._formatDSL(_count, mapping_path, op=_op), op, self._buildQKeys(op, _tc[0], _qk), _tc[1]  
	
	def _formatDefault(self, fields, mapping, op=DEFAULT_BOOL):
		if isinstance(fields, list):
			fields = "" . join(fields) #fields[0]
		default, _tc, _qk = self._parseQFields(fields)
		mapping_path = self._mapping_match(mapping, _tc[0])#tc[0])
		return self._formatDSL(default, mapping_path, op=op), op, self._buildQKeys(op, _tc[0], _qk), _tc[1]
	
	def _buildQKeys(self, op, field, addl=""):
		k = "%s,%s%s" %(op, field, addl)
		return k

	def _noEscape(self, qf):
		#date match
		if re.search("[0-9]{4}-[0-9]{2}-[0-9]{2}(T)?((([0-9]{2}(:)?)?){1,2,3})?", qf):
			return True
		return False

	def _parseQFields(self, q_fields, pq=None):
		parseReturn = {}
		q_fields = re.sub("('|\")", "", q_fields)
		if not self._noEscape(q_fields):
			q_fields = escapeESSpecialChars(q_fields)
		pq_split = "="
		qk = ""
		comp = "eq"
		_comp = {"eq": "==", "lte": "<=", "lt": "<", "gte": ">=", "gt": ">"}
		if q_fields.count("<") > 0:
			if not pq:
				pq = "range"
			if q_fields.count("<=") > 0:
				pq_split = "<="
				comp = "lte"
			else:
				pq_split = "<"
				comp = "lt"
		elif q_fields.count(">") > 0:
			if not pq:
				pq = "range"
			if q_fields.count(">=") > 0:
				pq_split = ">="
				comp = "gte"
			else:
				pq_split = ">"
				comp = "gt"
		else:
			if not pq:
				if re.search("[^\s]+\s+[^\s]+", q_fields.split(pq_split, 1)[1]):
					pq = "terms"
				else:
					pq = "term"
		_q_fields = q_fields.split(pq_split, 1)
		q_fields = [cleanAndLower(t, doLower=False) for t in _q_fields]
		if pq == "term":
			parseReturn.update({pq: {q_fields[0]: q_fields[1]}})
		elif pq == "terms":
			parseReturn.update({pq: {q_fields[0]: cleanAndLower(q_fields[1].split(" ")), "execution": "and"}})
		elif pq == "range":
			parseReturn.update({pq: {q_fields[0]: {comp: q_fields[1]}}})
			qk = "_%s" % comp
		elif pq == "count":
			parseReturn.update({"script": {"file": "field_cardinality", "lang": "groovy", "params": {"field": q_fields[0], "value_size": int(q_fields[1]), "operator": _comp[comp]}}})
			qk = "_%s" % comp
		return parseReturn, q_fields, qk

	def _mapping_match(self, mapping, query_key):
		mm = "_DEFAULT_"
		_qkey = re.split("<=|<|=|>|>=", query_key)[0]
		try:
			parent = _qkey.split(self.delimiter)[0]
			if mapping[parent] in ["nested"]:
				mm = parent
		except:
			pass
		return mm

	def _show(self, origq):
		q = {}
		if re.search("tables", origq, re.IGNORECASE):
			q.update({"_alias": "*"})
		elif re.search("columns", origq, re.IGNORECASE):
			q.update({"_mapping": None})
		return q

def test(debug):
	test_queries = [
		"SHOW COLUMNS FROM tst3",
		"EXPLAIN SELECT * FROM tst1",
		"EXPLAIN SELECT * FROM tst2 BETWEEN 2015-05-19 AND 2015-06-10 ORDER BY date_added ASC", 
		"EXPLAIN SELECT * FROM tst2 BETWEEN 2014-05-19 AND 2015-06-10 ORDER BY date_added ASC LIMIT 5",
		"EXPLAIN SELECT COUNT(DISTINCT(new_k)) FROM tst2 BETWEEN 2015-05-24 AND 2015-05-29", 
		"EXPLAIN SELECT COUNT(*) FROM tst2 BETWEEN 2015-05-24 AND 2015-05-29",
		"EXPLAIN SELECT * FROM tst2 WHERE (COUNT(tags)>=1 OR (uuid LIKE 'd24a4946.*' OR uuid LIKE '.*bfd72bbab3c4'))"
	]
	e = esql(debug=debug)
	for tq in test_queries:
		print("######")
		print("[QUERY] %s" % tq)
		print json.dumps(e.query(tq), indent=4)
		print("######")

def main():
	#q = "help"
	#q = "SHOW TABLES"
	try:
		q
	except:
		parser = argparse.ArgumentParser()
        	parser.add_argument("-c", "--cmd", nargs="+", help="provide a sql like command")
        	parser.add_argument("-t", "--test", action="store_true", default=False, help="run through test function")
        	parser.add_argument("-d", "--debug", action="store_true", default=False, help="run in debug mode - no logging of queries")
        	args = parser.parse_args()
		if not args.cmd and not args.test:
			args.cmd = ["help"]
		if args.test:
			test(args.debug)
			exit()
		q = ' ' . join(args.cmd)
	e = esql(debug=args.debug)
	print json.dumps(e.query(q), indent=4)

if __name__ == "__main__":
        main()
