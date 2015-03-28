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
                commands:       SELECT, SHOW
                clauses:        FROM, WHERE, LIMIT, OFFSET
                operands:       AND, OR, NOT
                comparisons:    =, <, <=, >=, >, LIKE
                sorting:        ORDER BY <FIELD> (DESC|ASC)
                ranges:         BETWEEN
                misc:           EXPLAIN, DISTINCT(<FIELD>(,<FIELD)), COUNT(<FIELD>)

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
                if not es_results or (es_results and len(es_results) == 0):
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
        #               (http://www.elasticsearch.org/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html#_boolean_operators)
        ###
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
                                ranges = cleanAndLower(_ranges, doLower=False)
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
                                where_dsl, qk, qv = self._buildDSL(temp_condition, mapping, temp_q)
                                if len(where_dsl) == 0:
                                        raise Exception("no where clause extracted")
                                q["query"]["filtered"].update({"filter": where_dsl})
                                q["query"]["filtered"].update({"query": { "match_all": {}}})
                                qkeys = qkeys + qk
                                qvals = qvals + qv
                                temp_q = False
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
			______q = "test"
                        #print("[qkeys] %s" % qkeys)
                        #print("[qvals] %s" % qvals)
                return q

        def _buildDSL(self, q, mapping, tq=None):
                last_mark = 1
                last_op = DEFAULT_OP
                temp_q = []
                build = {}
                for i, _q in enumerate(reversed(q)):
                        temp_q.append(_q)
                        if _q.lower() in ["and", "or", "not"]:
                                last_op = _q.lower()
                                if last_mark > 0:
                                        build = self._addTo(temp_q, last_op=last_op, build=build)
                                        temp_q = []
                                last_mark = i
                build = self._addTo(temp_q, last_op=last_op, build=build)
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
                                new_build = {"bool": {op: prep}}
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
                                                        new_build[0]["bool"][op].update(prep)
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
                _regexp = {"regexp": {fields[0]: re.sub("^('|\")|('|\")$", "", fields[2])}}
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
                        fields = "" . join(fields)
                default, _tc, _qk = self._parseQFields(fields)
                mapping_path = self._mapping_match(mapping, _tc[0])
                return self._formatDSL(default, mapping_path, op=op), op, self._buildQKeys(op, _tc[0], _qk), _tc[1]

        def _buildQKeys(self, op, field, addl=""):
                k = "%s,%s%s" %(op, field, addl)
                return k

        def _addTo(self, qlist, last_op=DEFAULT_OP, build=None):
                if not build:
                        build = {}
                op_map = {"and": "must", "or": "should", "not": "must_not"}
                _op = None
                field = []
                for q in qlist:
                        if q.lower() in ["and", "or", "not"]:
                                _op = op_map[q.lower()]
                                continue
                        field.append(q)
                if len(build) > 0:
                        if not _op:
                                _op = op_map[last_op.lower()]
                                build[_op].insert(0, field[::-1])
                        else:
                                temp_build = build
                                build = {}
                                build[_op] = [field[::-1], temp_build]
                else:
                        if not _op:
                                _op = op_map[last_op.lower()]
                        build[_op] = [field[::-1]]
                return build

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
