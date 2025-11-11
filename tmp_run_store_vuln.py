from core import redis as core_redis
v = {'ip':'127.0.0.1','port':80,'rule_id':'TEST-1','rule_details':'openssl vulnerability'}
print('Using rds mock?', getattr(core_redis.rds, 'is_mock', None))
core_redis.rds.store_vuln(v)
print('store_vuln completed, v now has cve_ids?:', 'cve_ids' in v)
