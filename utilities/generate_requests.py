# This is not part of the actual server
# Run after generating users

import os, psycopg2, random
from urllib.parse import urlparse

urlparse.uses_netloc.append("postgres")
url = urlparse.urlparse(os.environ["DATABASE_URL"])

db = psycopg2.connect(database=url.path[1:],
                      user=url.username,
                      password=url.password,
                      host=url.hostname,
                      port=url.port)
c = db.cursor()

c.execute('''CREATE TABLE requests
             (from_who text,
              to_who text,
              message text)''')

users = {'user' + str(i) for i in range(11)}

for i in range(11):
    if random.randint(0, 1):
        c.execute('''SELECT friends FROM users WHERE name = %s''', ('user' + str(i),))
        friends = c.fetchone()[0].split(',')
        friends.append('user' + str(i))
        rec = random.choice(list(users.difference(friends)))
        c.execute('''INSERT INTO requests VALUES
                     (%s, %s, 'Hey, add me')''',
                  ('user' + str(i), rec))

db.commit()
db.close()
