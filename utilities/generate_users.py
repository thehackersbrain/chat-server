# This is not part of the actual server
# Run after generating messages

from hashlib import sha256
from urllib.parse import urlparse
import os, random, psycopg2

def cjoin(ls):
    return ','.join(map(str, ls))

def get_dialogs(name):
    res = []
    for i in range(16):
        c.execute('''SELECT sender FROM d{} WHERE sender = %s'''.format(i), (name,))
        if c.fetchone():
            res.append(i)
    return res

urlparse.uses_netloc.append("postgres")
url = urlparse.urlparse(os.environ["DATABASE_URL"])

db = psycopg2.connect(database=url.path[1:],
                      user=url.username,
                      password=url.password,
                      host=url.hostname,
                      port=url.port)
c = db.cursor()

users = ['user' + str(i) for i in range(11)]

c.execute('''CREATE TABLE users
             (name text PRIMARY KEY,
              password text,

              friends text,
              favorites text,
              blacklist text,
              dialogs text)''')

c.execute('''CREATE TABLE profiles
             (name text PRIMARY KEY
              REFERENCES users(name),
              status text,
              email text,
              birthday int,
              about text,
              image bytea)''')

for user in users:
    pswd = (user + '2016')[::-1] + 'mysaslt'
    sha = sha256(pswd.encode())

    friends = list({random.choice(users) for i in range(random.randint(1,5))})
    favorites = random.choice(friends)
    blacklist = random.choice(list(set(users).difference(friends)))
    dl = cjoin(get_dialogs(user))
    c.execute('''INSERT INTO users VALUES
                 (%s, %s, %s, %s, %s, %s)''',
    (user,
    sha.hexdigest(),
    cjoin(friends),
    favorites,
    blacklist,
    dl))

    c.execute('''INSERT INTO profiles VALUES
    (%s, %s, %s, %s, %s, %s)''',
    (user,
    '',
    'undefined',
    1355292732,
    'I am ' + user,
    psycopg2.Binary(b'lolno')))

db.commit()
db.close()
