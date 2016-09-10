from pgdb import connect

db = connect(user='postgres',
             password='levameow',
             host='localhost',
             database='chat')
c = db.cursor()

c.execute('''SELECT * FROM sessions''')
db.commit()
print(c.fetchall())
