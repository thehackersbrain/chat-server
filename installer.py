import os, psycopg2
from urllib.parse import urlparse

class Installer:
    @staticmethod
    def install():
        url = urlparse(os.environ["DATABASE_URL"])

        db = psycopg2.connect(database=url.path[1:],
                              user=url.username,
                              password=url.password,
                              host=url.hostname,
                              port=url.port)
        c = db.cursor()

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
                                            birthday int,
                                            about text,
                                            image bytea)''')

        c.execute('''CREATE TABLE sessions (name text,
                                            session_id text UNIQUE,
                                            ip text)''')

        c.execute('''CREATE TABLE requests (from_who text,
                                            to_who text,
                                            message text)''')

        db.commit()
        db.close()

if __name__ == '__main__':
    Installer.install()
