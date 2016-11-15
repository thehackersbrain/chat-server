import logging, psycopg2
from datetime import datetime, timedelta
from urllib.parse import urlparse

log_level = logging.DEBUG

log = logging.Logger('session_cleaner')
log.setLevel(log_level)

log_handler = logging.StreamHandler()
log_handler.setLevel(log_level)

log_fmt = logging.Formatter('[{asctime}] [{levelname}]\n{message}\n',
                            datefmt = '%d-%m %H:%M:%S', style = '{')
log_handler.setFormatter(log_fmt)

log.addHandler(log_handler)

url = urlparse(os.environ["DATABASE_URL"])

db = psycopg2.connect(database=url.path[1:],
                      user=url.username,
                      password=url.password,
                      host=url.hostname,
                      port=url.port)

c = db.cursor()

log.info('starting up')

# Получаем текущую дату и время
stamp = datetime.now()
log.debug('current timestamp is' + str(stamp.timestamp()))

# Вычитаем два часа
stamp -= timedelta(hours = 2)
log.debug('will remove everything older than' + str(stamp.timestamp()))

# Удаляем все записи, в которых время меньше stamp
c.execute('''DELETE FROM sessions
             WHERE last_active < %s''', (str(stamp.timestamp()), ))
log.info('done')

db.commit()
c.close()
db.close()
