# This is not part of the actual server

from time import time
from urllib.parse import urlparse
import os, random, psycopg2

urlparse.uses_netloc.append("postgres")
url = urlparse.urlparse(os.environ["DATABASE_URL"])

db = psycopg2.connect(database=url.path[1:],
                      user=url.username,
                      password=url.password,
                      host=url.hostname,
                      port=url.port)
c = db.cursor()

for file_id in range(16):
    c.execute('''CREATE TABLE d{}
                 (content text,
                  timestamp bigint,
                  sender text)'''.format(file_id))
    users = [random.randint(0, 10), random.randint(0, 10)]
    for msg_num in range(20):
        msg_record = ('Some, text', int(time() * 100),
                      'user' + str(random.choice(users)))
        c.execute('''INSERT INTO d{} VALUES (%s, %s, %s)'''.format(file_id), msg_record)

db.commit()
db.close()
