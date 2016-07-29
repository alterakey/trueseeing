import sqlite3
import re

if __name__ == '__main__':
    def fn(expr, item):
        return (item is not None) and (re.compile(expr).search(item) is not None)

    with sqlite3.connect('store.db') as c:
        c.create_function('REGEXP',2,fn)
        for r in c.execute("select distinct v2 from op_vecs where (v like 'invoke%') and (v2 regexp '^Landroid[a-z0-9/]+[A-Z]') and not (v2 like '%support%')"):
            print(r)
