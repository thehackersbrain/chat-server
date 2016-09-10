# This is not part of the actual server
# Independent execution

from hashlib import sha256
from urllib.parse import urlparse
import os, psycopg2, random

urlparse.uses_netloc.append("postgres")
url = urlparse.urlparse(os.environ["DATABASE_URL"])

db = psycopg2.connect(database=url.path[1:],
                      user=url.username,
                      password=url.password,
                      host=url.hostname,
                      port=url.port)
c = db.cursor()

online = {'user' + str(random.randint(0, 10)) for i in range(random.randint(2, 10))}

def get_ip(st):
    num = st[4:]
    return '.'.join([num] * 4)

c.execute('''CREATE TABLE sessions
             (name text,
             session_id text UNIQUE,
             ip text)''')

for i in online:
    sha = sha256((get_ip(i) + i).encode())
    c.execute('''INSERT INTO sessions VALUES
                 (%s, %s ,%s)''',
                 (i,
                 sha.hexdigest(),
                 get_ip(i)))

db.commit()
db.close()
