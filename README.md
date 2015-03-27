# esql
SQL like interface to Elasticsearch

#requirements
* requests
  * http://docs.python-requests.org/en/latest/
* within Elasticsearch, aliases must be assigned for all indices

#overview
This started as quick code to allow an easier entry level to the Elastic DSL.  I've tried to adhere to the filter
bitsets and when to use bool and and/or/not.  A groovy script is used for COUNT() when used as a selection criteria; 
this should be stored on each Elasticsearch server used for queries.

#issues
When using COUNT(), the Elasticsearch breaker system has been tripped on fields that contain large amounts of data.
Further, this seems to be more of an occurrence when using COUNT(field)<op>, where <op> is >, =, <.  The same query
using <=, >= appear to work fine.  If you notice this issue, try the same query with multiple COUNT()'s and combinations
of <= and >=.

#configure
  * within esql.py, set the following key/values pairs in self.es_conf:
    * hosts: list of Elasticsearch hosts
    * port: which port to connect to Elasticsearch on
    * delimiter: delimiter to use when flattening mappings; if not sure, leave as "."
    * timeout: timeout for connection to Elasticsearch hosts
    * user: I used nginx to proxy Elasticsearch, because of this, a user and password were needed.  set to None
    if not needed
    * password: used with user above.  set to None if not needed
    * date_mapping: for each index, name the mapping field that would be used to for BETWEEN date ranges

#what is supported
  * commands:
    * SELECT, SHOW
  * clauses:
    * FROM, WHERE, LIMIT, OFFSET
  * operands:
    * AND, OR, NOT
  * comparisons:
    * =, <, <=, >=, >, LIKE
  * sorting:
    * ORDER BY <FIELD> (DESC|ASC)
  * ranges:
    * BETWEEN
  * misc:
    * EXPLAIN, DISTINCT(<FIELD>(,<FIELD>)), COUNT(<FIELD>)

#examples
```
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
```
#caveats
  * using COUNT for a SELECT, e.g SELECT COUNT(field) FROM <TABLE>, will use the _count API and will return the 
  total count for the given query
  * using COUNT(DISTINCT(field)) for a SELECT, e.g. SELECT COUNT(DISTINCT(field)) FROM <TABLE>, will use _search API
  and DISTINCT will be handled in esql.  Because of this, you may have fewer results returned than expected if a 
  LIMIT clause is also provided.
