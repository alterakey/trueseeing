import sqlite3
import re

if __name__ == '__main__':
    def fn(expr, item):
        return (item is not None) and (re.compile(expr).search(item) is not None)

    with sqlite3.connect('store.db') as c:
        for r in c.execute("select select x,(select min(op) from op_vecs where op>x and (t='directive' and v='end' and v1='method')) as y from (select op as x from ops where t='directive' and v='method')"):
            print(r)
