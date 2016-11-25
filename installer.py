import os, psycopg2, rsa
from urllib.parse import urlparse


class Installer:
    def connect(self):
        self.url = urlparse(os.environ["DATABASE_URL"])

        self.db = psycopg2.connect(database=self.url.path[1:],
                                   user=self.url.username,
                                   password=self.url.password,
                                   host=self.url.hostname,
                                   port=self.url.port)

    def create_database(self):
        c = self.db.cursor()

        c.execute('''CREATE TABLE users (name text PRIMARY KEY,
                                         password text,

                                         friends text ARRAY,
                                         favorites text ARRAY,
                                         blacklist text ARRAY,
                                         dialogs text ARRAY)''')

        c.execute('''CREATE TABLE profiles (name text PRIMARY KEY
                                            REFERENCES users(name),

                                            status text,
                                            email text,
                                            birthday bigint,
                                            about text,
                                            image bytea)''')

        c.execute('''CREATE TABLE sessions (name text,
                                            pub_key text ARRAY,
                                            ip text UNIQUE,
                                            last_active bigint)''')

        c.execute('''CREATE TABLE requests (from_who text,
                                            to_who text,
                                            message text)''')

        c.execute('''CREATE TABLE key (pub_key text ARRAY,
                                       priv_key text ARRAY)''')

        self.db.commit()
        c.close()

    def seed_database(self):
        pubkey, privkey = rsa.newkeys(2048, accurate = False)

        c = self.db.cursor()
        c.execute('''INSERT INTO key VALUES (%s, %s)''',
                  (list(map(str, pubkey.__getstate__())),
                   list(map(str, privkey.__getstate__()))))

        c.close()
        self.db.commit()
        self.db.close()

    def install(self):
        self.connect()
        self.create_database()
        self.seed_database()


if __name__ == '__main__':
    Installer().install()
