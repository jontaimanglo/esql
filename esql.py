#!/usr/bin/env python
import re, argparse, collections
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
class esql:
	def __init__(self):
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
		#print("[DEBUG] %s, %s" %(final_q, json.dumps(final_d, indent=4)))
		try:
			if self.es_conf["user"] and self.es_conf["password"]:
				es_results = urlQuery(self.es_hosts, [final_q], auth=HTTPBasicAuth(self.es_conf['user'], self.es_conf['password']), data=[final_d], verify=False, timeout=self.timeout, returnErr=True)
			else:
				es_results = urlQuery(self.es_hosts, [final_q], data=[final_d], verify=False, timeout=self.timeout, returnErr=True)
		except Exception, err:
			return {'error': "%s" % err}
		if not es_results:
			return {'info': 'no results found'}
		if len(es_results) > 0:
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
								dsl = "%s/_count" % qk
							else:
								dsl = "%s/_search" % qk
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
		res = collections.OrderedDict()
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
					try:
						res[idx]
					except:
						_temp_res = rv["mappings"].values()[0]
						res[idx] = _temp_res["properties"]
		elif t == "select" or t == "explain":
			self._distinct = {}
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

	# references: http://stackoverflow.com/questions/6027558/flatten-nested-python-dictionaries-compressing-keys
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

	# references: boolean operators (+/-) in queries: 
	#		(http://www.elasticsearch.org/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html#_boolean_operators)
	def _select(self, origq, index, mapping):
		q = {}
		temp_q = {}
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
				fields =[cleanAndLower(f, doLower=False) for f in _fields.split(",")]
				if (self.total_count and self.distinct) or not self.total_count:
					#q.update({"fields": fields})
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
				#size argument is not supported when using _count API
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
				op = "must"
				_op = {"must": "and", "should": "or", "must_not": "not"}
				rgx = -1
				opn_prn = _op[op]
				cls_prn = False
				query_map = {}
				for i, tc in enumerate(temp_condition):
					tc = cleanAndLower(tc, doLower=False)
					if i == rgx or re.search("^(\s+)?like(\s+)?", tc, re.IGNORECASE):
						continue
					if not tc or re.search("^\s+$", tc):
						continue
					if re.search("^(\s+)?and(\s+)?$", tc, re.IGNORECASE):
						op = "must"
						rgx = False
						continue
					elif re.search("^(\s+)?or(\s+)?$", tc, re.IGNORECASE):
						op = "should"
						rgx = False
						continue
					elif re.search("^(\s+)?not(\s+)?$", tc, re.IGNORECASE):
						op = "must_not"
						rgx = False
						continue
					opn_prn = _op[op]
					'''
					if tc == "(":
						cls_prn = opn_prn
						continue
					elif tc == ")":
						cls_prn = False
						continue
					'''
					try:
						if re.search("^count\([^\)]+\)", tc, re.IGNORECASE):
							count = re.sub("count|\(|\)", "", tc, flags=re.IGNORECASE)
							mapping_path = self._mapping_match(mapping, count)
							_count, _tc, _qk = self._parseQFields(count, pq="count")
							query_map = self._query_map_update(query_map, mapping_path, opn_prn, _count, cls_prn)
							continue	
					except:
						pass
					try:
						next_cond_num = i + 1
						if re.search("^(\s+)?like(\s+)?", temp_condition[next_cond_num], re.IGNORECASE):
							_regexp = {"regexp": {tc: re.sub("^('|\")|('|\")$", "", temp_condition[next_cond_num + 1])}}
							mapping_path = self._mapping_match(mapping, tc)
							query_map = self._query_map_update(query_map, mapping_path, op, _regexp, cls_prn)
							rgx = next_cond_num + 1
							continue
					except:
						pass
					_non_regexp, _tc, _qk = self._parseQFields(tc)
					mapping_path = self._mapping_match(mapping, _tc[0])#tc[0])
					query_map = self._query_map_update(query_map, mapping_path, op, _non_regexp, cls_prn)
				if len(query_map) == 0:
					raise Exception("no query map data")	
				q["query"]["filtered"].update({"query": { "match_all": {}}})
				for qk, qv in query_map.iteritems():
					_andQ = []
					_orQ = []
					_notQ = []
					_mustQ = []
					_shouldQ = []
					_must_notQ = []
					for nk, nv in qv.iteritems():
						if nk == "and":
							_andQ = _andQ + nv
						elif nk == "or":
							_orQ = _orQ + nv
						elif nk == "not":
							_notQ = _notQ + nv
						elif nk == "must":
							_mustQ = _mustQ + nv
						elif nk == "should":
							_shouldQ = _shouldQ + nv
						elif nk == "must_not":
							_must_notQ = _must_notQ + nv
					if len(_andQ) > 0:
						temp_q.update({"and": _andQ})
						op = True
					if len(_orQ) > 0:
						temp_q.update({"or": _orQ})
					if len(_notQ) > 0:
						temp_q.update({"not": _notQ})
					if len(_mustQ) > 0:
						try:
							existing_mustQ = temp_q["must"]
						except:
							existing_mustQ = []
						if not isinstance(existing_mustQ, list):
							existing_mustQ = [existing_mustQ]
						mustQ = existing_mustQ + _mustQ
						try:
							temp_q["and"].append({"bool": {"must": mustQ}})
							try:
								del temp_q["must"]
							except Exception, err:
								pass
						except:
							temp_q.update({"must": mustQ})
					else:
						try:
							temp_q["and"].append({"bool": {"must": temp_q["must"]}})
							try:
								del temp_q["must"]
							except:
								pass
						except:
							pass
					if len(_shouldQ) > 0:
						try:
							temp_q["or"].append({"bool": {"should": _shouldQ}})
							try:
								del temp_q["should"]
							except:
								pass
						except:
							temp_q.update({"should": _shouldQ})
					if len(_must_notQ) > 0:
						try:
							temp_q["not"].append({"bool": {"must_not": _must_notQ}})
							try:
								del temp_q["must_not"]
							except:
								pass
						except:
							temp_q.update({"must_not": _must_notQ})
					if not qk == "_DEFAULT_":
						_qk = mapping[qk]
						ttq = temp_q
						temp_q = {}
						temp_q.update({"must": { _qk: {"path": qk, "filter": {"bool": ttq}}}})
					if len(_andQ) > 0 or len(_orQ) > 0 or len(_notQ) > 0:
						if len(_andQ) > 0:
							q = self._buildQueryDict(q, "and", t=[])
						if len(_orQ) > 0:
							q = self._buildQueryDict(q, "or", t=[])
						if len(_notQ) > 0:
							q = self._buildQueryDict(q, "not", t=[])
					else:
						q = self._buildQueryDict(q, "bool")
					opCheck = {}
					for tk, tv in temp_q.iteritems():
						_tk = tk
						if tk in ["must", "must_not", "should"]:
							_tk = "bool"
						curr_tv = []
						try:
							opCheck[_tk]
							if _tk == "bool":
								existing_tv = q["query"]["filtered"]["filter"]["bool"][tk]
							else:
								existing_tv = q["query"]["filtered"]["filter"][tk]
							if not isinstance(existing_tv, list):
								existing_tv = [existing_tv]
						except:
							opCheck.update({tk: 1})
							try:
								if _tk == "bool":
									curr_tv = q["query"]["filtered"]["filter"]["bool"][tk]
								else:
									curr_tv = q["query"]["filtered"]["filter"][tk]
								if len(curr_tv) > 0:
									if not isinstance(curr_tv, list):
										curr_tv = [curr_tv]
								else:
									curr_tv = []
							except:
								pass
							existing_tv = []
						if not isinstance(tv, list):
							tv = [tv]
						final_tv = curr_tv + tv + existing_tv
						if _tk == "bool":
							try:
								q["query"]["filtered"]["filter"]["bool"][tk] = final_tv
							except:
								q["query"]["filtered"]["filter"].update({"bool": {tk: final_tv}})
						else:
							q["query"]["filtered"]["filter"][tk] = final_tv
					temp_q = False
			except Exception, err:
				if re.search("where", origq, re.IGNORECASE):
					print("[ERROR] Unable to extract where from '%s': %s" %(repr(origq), err))
					return {'error': 'unable to extract where clause'}
		try:
			#if q["fields"][0] == "*":
			#	del q["fields]
			if q["_source"][0] == "*":
				del q["_source"]
		except:
			pass
		if temp_q:
			q["query"]["filtered"].update({"filter": {"bool": temp_q}})
		return q

	def _buildQueryDict(self, q, op, t={}):
		try:
			q["query"]["filtered"]["filter"][op]
		except:
			try:
				q["query"]["filtered"]["filter"].update({op: t})
			except:
				q["query"]["filtered"].update({"filter": {op: t}})
		return q

	def _query_map_update(self, query_map, mpath, op, v, subop=None):
		try:
			query_map[mpath]
		except:
			query_map.update({mpath: {}})
		try:
			query_map[mpath][op]
			if not subop:
				query_map[mpath][op].append(v)
			else:
				try:
					query_map[mpath][op][subop].append(v)
				except:
					query_map[mpath][op].update({subop: [v]})
		except:
			if not subop:
				query_map[mpath].update({op: [v]})
			else:
				query_map[mpath].update({op: {subop: [v]}})
		return query_map

	def _parseQFields(self, q_fields, pq=None):
		parseReturn = {}
		q_fields = re.sub("('|\")", "", q_fields)
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
				pq = "term"
		_q_fields = q_fields.split(pq_split, 1)
		q_fields = [cleanAndLower(t, doLower=False) for t in _q_fields]
		if pq == "term":
			parseReturn.update({pq: {q_fields[0]: q_fields[1]}})
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
	
def main():
	#q = "help"
	#q = "SHOW TABLES"
	#q = "SHOW COLUMNS FROM uris"
	#q = "SELECT * FROM uris BETWEEN 2015-02-03T00:10:20 AND 2015-02-03T12:30:58 ORDER BY date_added DESC LIMIT 1 OFFSET 10"
	#q = "SELECT uri_sig, uri FROM uris WHERE uri='amazon.com' BETWEEN 2015-01-30T00:05:30 AND 2015-01-30T05:05:29 ORDER BY date_added DESC LIMIT 10"
	try:
		q
	except:
		q = None
	if not q:
		parser = argparse.ArgumentParser()
        	parser.add_argument("-c", "--cmd", nargs="+", help="provide a sql like command")
        	args = parser.parse_args()
		if not args.cmd:
			args.cmd = ["help"]
		q = ' ' . join(args.cmd)
	e = esql()
	print json.dumps(e.query(q), indent=4)

if __name__ == "__main__":
        main()
