import psycopg2, psycopg2.extras
import json, re, os
from urllib.parse import urlparse
from hashlib import sha256

sample_img = (b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
              b'\x00\x00\x00\x01\x00\x00\x00\x01\x08'
              b'\x02\x00\x00\x00\x90wS\xde\x00\x00\x00'
              b'\x0cIDATx\x9cc```\x00\x00\x00\x04\x00'
              b'\x01\xf6\x178U\x00\x00\x00\x00IEND\xaeB`\x82')

class BadRequest(Exception):
    """Класс исключений для индикации логической ошибки в запросе"""

class ClientCodes():
    """Перечисление кодов запросов от клиента"""
    register = 0
    login = 1
    search_username = 2
    friends_group = 3
    get_message_history = 4
    send_message = 5
    new_message_received = 6
    change_profile_section = 7
    add_to_blacklist = 8
    delete_from_friends = 9
    send_request = 10
    delete_profile = 11
    friends_group_update_succ = 12
    new_add_request_received = 13
    add_request_confirm_received = 14
    logout = 15
    create_dialog = 16
    get_profile_info = 17
    remove_from_blacklist = 18
    take_request_back = 19
    confirm_add_request = 20
    add_to_favorites = 21
    delete_dialog = 22
    add_request_decline_received = 23
    search_msg = 24
    remove_from_favorites = 25
    get_add_requests = 26
    decline_add_request = 27
    set_image = 28

class ServerCodes():
    """Перечисление кодов запросов от сервера"""
    login_error = 0
    register_error = 1
    login_succ = 2
    register_succ = 3
    search_username_result = 4
    friends_group_response = 5
    message_history = 6
    message_received = 7
    new_message = 8
    change_profile_section_succ = 9
    friends_group_update = 10
    add_to_blacklist_succ = 11
    delete_from_friends_succ = 12
    send_request_succ = 13
    new_add_request = 14
    add_request_confirm = 15
    delete_profile_succ = 16
    logout_succ = 17
    create_dialog_succ = 18
    profile_info = 19
    remove_from_blacklist_succ = 20
    take_request_back_succ = 21
    confirm_add_request_succ = 22
    add_to_favorites_succ = 23
    delete_dialog_succ = 24
    add_request_decline = 25
    search_msg_result = 26
    remove_from_favorites_succ = 27
    add_requests = 28
    decline_add_request_succ = 29
    set_image_succ = 30

cc = ClientCodes
sc = ServerCodes

# Add notificators about events

class Processor:
    # Парсинг ссылки на базу данных
    url = urlparse(os.environ["DATABASE_URL"])

    db = psycopg2.connect(database=url.path[1:],
                          user=url.username,
                          password=url.password,
                          host=url.hostname,
                          port=url.port,
                          cursor_factory = psycopg2.extras.DictCursor)

    # Регулярное выражение для валидации имен пользователей
    nick_ptrn = re.compile('(?![ ]+)[\w ]{2,15}')

    def _add_session(self, nick, ip):
        """Добавляет пользователя nick по IP-адресу ip в таблицу сессий
        Вызывает BadRequest, если такая комбинация данных уже есть в таблице"""
        sha = sha256((nick + ip).encode())
        session_id = sha.hexdigest()
        c = self.db.cursor()
        try:
            with self.db:
                c.execute('''INSERT INTO sessions
                             VALUES (%s, %s, %s)''',
                          (nick, session_id, ip))
        except psycopg2.IntegrityError:
            raise BadRequest
        c.close()
        return session_id

    def _check_session(self, session_id, ip):
        """Проверяет, есть ли активная сессия с идентификатором id и IP-адресом ip
        Возвращает имя пользователя, записанного под этим идентификатором
        Вызывает BadRequest, если такой записи нет"""
        c = self.db.cursor()
        c.execute('''SELECT name FROM sessions
                     WHERE session_id = %s AND ip = %s''',
                  (session_id, ip))
        nick = c.fetchone()
        c.close()
        if nick:
            return nick['name']
        raise BadRequest()

    def _pack(self, *data):
        """Собирает данные data в формат для передачи
        Возвращает отформатированную байт-строку"""
        return json.dumps(data, separators = (',', ':'))[1:-1].encode()

    def _close_session(self, session_id):
        """Удаляет из таблицы сессий запись с идентификатором session_id"""
        c = self.db.cursor()
        with self.db:
            c.execute('''DELETE FROM sessions
                         WHERE session_id = %s''', (session_id,))

        c.close()

    def _remove_from(self, nick, item, sect):
        """Удаляет элемент item из графы sect в записи с именем nick
        Вызывает BadRequest, если пользователь nick не найден
        """
        c = self.db.cursor()
        c.execute('''SELECT {}::text[] FROM users
                     WHERE name = %s'''.format(sect), (nick,))

        prev = c.fetchone()
        if not prev:
            raise BadRequest
        data = prev[sect]
        try:
            data.remove(item)
        except ValueError:
            pass  # Если элемента нет, проигнорировать исключение
        with self.db:
            c.execute('''UPDATE users SET {} = %s
                         WHERE name = %s'''.format(sect), (data, nick))

        c.close()

    def _is_blacklisted(self, nick, user):
        """Проверяет, находится ли nick в черном списке user"""
        c = self.db.cursor()
        if nick == user:
            return False
        c.execute('''SELECT name FROM users
                     WHERE name = %s AND %s = ANY(blacklist::text[])''',
                  (user, nick))
        return bool(c.fetchone())

    def _remove_add_request(self, nick, user):
        """Удаляет запрос от nick к user"""
        c = self.db.cursor()
        with self.db:
            c.execute('''DELETE FROM requests
                         WHERE from_who = %s AND to_who = %s''',
                      (nick, user))

        c.close()

    def _add_to(self, nick, item, sect):
        """Добавляет элемент item к графе sect в записи с именем nick
        Вызывает BadRequest, если пользователь nick не найден"""
        c = self.db.cursor()

        c.execute('''SELECT {}::text[] FROM users
                     WHERE name = %s'''.format(sect), (nick,))

        prev = c.fetchone()
        if not prev:
            raise BadRequest
        data = prev[sect]
        if item in data:
            return  # Если элемент уже есть, не добавлять его еще раз
        data.append(item)
        with self.db:
            c.execute('''UPDATE users SET {} = %s
                         WHERE name = %s'''.format(sect),
                      (data, nick))

        c.close()

    def _user_in_dialog(self, user, dialog):
        """Проверяет, что диалог под номером dialog есть
        в графе диалогов пользователя user
        Вызывает BadRequest, если пользователь не найден,
        диалога dialog нет в графе или dialog не является целым числом"""
        if not isinstance(dialog, int):
            raise BadRequest
        c = self.db.cursor()
        c.execute('''SELECT dialogs FROM users
                     WHERE name = %s AND %s = ANY(dialogs::text[])''',
                  (user, str(dialog)))
        if not c.fetchone():
            raise BadRequest

        c.close()

    def _delete_dialog(self, dialog, user):
        """Удаляет диалог под номером dialog по запросу пользователя user
        Если собеседник удалил для себя этот диалог, таблица диалога удаляется.
        Иначе пользователь, от кого поступил запрос на удаление,
        помечается как удаливший этот диалог для себя"""
        c = self.db.cursor()
        c.execute('''SELECT sender FROM d{}
                     WHERE sender != %s'''.format(dialog), (user,))
        sender = c.fetchone()
        if not sender or sender['sender'][0] == '~':
            c.execute('''DROP TABLE d{}'''.format(dialog))
        else:
            c.execute('''UPDATE d{} SET sender = '~' || %s
                         WHERE sender = %s'''.format(dialog),
                                                  (user, user))
        # Диалог с номером dialog удаляется из диалогов пользователя user
        self._remove_from(user, str(dialog), 'dialogs')
        self.db.commit()

        c.close()

    def _user_exists(self, user):
        """Проверяет, что пользователь user существует
        Вызывает BadRequest в противном случае"""
        c = self.db.cursor()
        c.execute('''SELECT name FROM users
                     WHERE name = %s''', (user,))
        if not c.fetchone():
            raise BadRequest

        c.close()

    def _valid_nick(self, nick):
        """Проверяет, является ли nick допустимым именем пользователя"""
        return bool(re.fullmatch(self.nick_ptrn, nick))

    def _next_free_dialog(self):
        """Возвращает следующий свободный номер диалога"""
        c = self.db.cursor()
        c.execute('''SELECT table_name FROM information_schema.tables
                     WHERE table_schema = 'public' ''')
        dialogs = sorted(int(i['table_name'][1:]) for i in c.fetchall()
                         if i['table_name'][0] == 'd')
        for i in range(1, len(dialogs)):
            if dialogs[i] - dialogs[i - 1] != 1:
                c.close()
                return dialogs[i - 1] + 1
        c.close()
        return dialogs[-1] + 1


    def register(self, request_id, ip, nick, pswd):
        """Зарегистрироваться с именем nick и хэшем pswd пароля"""
        if not self._valid_nick(nick):
            return self._pack(sc.register_error, request_id)

        c = self.db.cursor()

        try:
            with self.db:
                c.execute('''INSERT INTO users
                             VALUES (%s, %s,
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''',
                         (nick, pswd))

                c.execute('''INSERT INTO profiles
                             VALUES (%s, '', '', 0, '', E'')''', (nick,))
        except psycopg2.IntegrityError:
            # Если пользователь с таким именем существует
            return self._pack(sc.register_error, request_id)

        session_id = self._add_session(nick, ip)

        c.close()
        return self._pack(sc.register_succ, request_id, session_id)

    def login(self, request_id, ip, nick, pswd):
        """Войти в систему с именем nick и хэшем pswd пароля"""
        c = self.db.cursor()
        c.execute('''SELECT name FROM users
                     WHERE name = %s AND password = %s''', (nick, pswd))
        if not c.fetchone():
            # Если такой комбинации имени-пароля нет
            return self._pack(sc.login_error, request_id)

        try:
            session_id = self._add_session(nick, ip)
        except BadRequest:
            return self._pack(sc.login_error, request_id)

        c.close()
        return self._pack(sc.login_succ, request_id, session_id)

    def search_username(self, request_id, ip, session_id, user):
        """Найти среди пользователей тех, чье имя содержит подстроку user"""
        c = self.db.cursor()
        self._check_session(session_id, ip)
        c.execute('''SELECT name FROM users
                     WHERE POSITION(%s IN name) > 0''', (user,))
        search_results = [row['name'] for row in c.fetchall()]
        c.close()
        return self._pack(sc.search_username_result, request_id,
                          search_results)

    def friends_group(self, request_id, ip, session_id):
        """Получить список друзей, сгрупированных в списки:
        онлайн, оффлайн, избранные, черный список"""
        c = self.db.cursor()
        nick = self._check_session(session_id, ip)
        c.execute('''SELECT friends::text[],
                            favorites::text[],
                            blacklist::text[]
                     FROM users WHERE name = %s''', (nick,))
        friends, fav, bl = c.fetchone()

        c.execute('''SELECT name FROM sessions''')
        online_all = {i['name'] for i in c.fetchall()}

        online = []
        offline = []
        for i in friends:
            if i in online_all:
                online.append(i)
            else:
                offline.append(i)
        c.close()
        return self._pack(sc.friends_group_response, request_id,
                          [online, offline, fav, bl])

    def message_history(self, request_id, ip, session_id, count, dialog):
        """Получить count последних сообщений из диалога dialog
        Если count = 0, возвращает все сообщения
        Вызывает BadRequest, если count < 0"""
        c = self.db.cursor()
        if count < 0:
            raise BadRequest

        nick = self._check_session(session_id, ip)
        self._user_in_dialog(nick, dialog)

        c.execute('''SELECT * FROM d{}
                     ORDER BY timestamp'''.format(dialog))
        msgs = [tuple(i) for i in c.fetchall()]
        c.close()
        return self._pack(sc.message_history, request_id, msgs[-count:])

    def send_message(self, request_id, ip, session_id, msg, tm, dialog):
        """Отправить сообщение msg с временем tm в диалог под номером dialog
        Вызывает BadRequest, если отправитель находится в черном списке
        собеседника или длина сообщения превышает 1000 символов"""
        max_msg_length = 1000
        if len(msg) > max_msg_length:
            raise BadRequest
        nick = self._check_session(session_id, ip)
        self._user_in_dialog(nick, dialog)

        c = self.db.cursor()
        c.execute('''SELECT sender FROM d{}
                     WHERE sender != %s'''.format(dialog), (nick,))
        user = c.fetchone()
        if user and self._is_blacklisted(nick, user['sender']):
            raise BadRequest

        with self.db:
            c.execute('''INSERT INTO d{}
                         VALUES (%s, %s, %s)'''.format(dialog),
                      (msg, tm, nick))
        c.close()
        return self._pack(sc.message_received, request_id)

    def change_profile_section(self, request_id, ip, session_id, sect, change):
        """Заменить секцию профиля sect на change
        Вызывает BadRequest, если дата рождения (секция 2)
        меняется на что-то кроме целого числа
        или указана несуществующая секция"""
        nick = self._check_session(session_id, ip)

        birthday = 2
        if not isinstance(change, int) and sect == birthday:
            raise BadRequest

        sections = {0: 'status',
                    1: 'email',
                    2: 'birthday',
                    3: 'about'}

        try:
            sect_name = sections[sect]
        except KeyError:
            raise BadRequest

        c = self.db.cursor()
        with self.db:
            c.execute('''UPDATE profiles SET {} = %s
                         WHERE name = %s'''.format(sect_name),
                      (change, nick))
        c.close()
        return self._pack(sc.change_profile_section_succ, request_id)

    def add_to_blacklist(self, request_id, ip, session_id, user):
        """Добавить пользователя user в черный список
        Вызывает BadRequest, если отправитель пытается добавить себя"""
        nick = self._check_session(session_id, ip)
        self._user_exists(user)
        if nick == user:
            raise BadRequest
        self._remove_from(nick, user, 'friends')
        self._remove_from(nick, user, 'favorites')
        self._add_to(nick, user, 'blacklist')
        self._remove_add_request(nick, user)
        self._remove_add_request(user, nick)
        return self._pack(sc.add_to_blacklist_succ, request_id)

    def delete_from_friends(self, request_id, ip, session_id, user):
        """Удалить пользователя user из друзей"""
        nick = self._check_session(session_id, ip)
        self._user_exists(user)
        self._remove_from(nick, user, 'friends')
        self._remove_from(nick, user, 'favorites')
        return self._pack(sc.delete_from_friends_succ, request_id)

    def send_request(self, request_id, ip, session_id, user, msg):
        """Отправить пользователю user запрос на добавление с сообщением msg
        Вызывает BadRequest, если уже отправлен запрос этому пользователю
        или отправитель пытается отправить запрос на добавление себе
        или тому, в чьем черном списке или друзьях он находится"""
        nick = self._check_session(session_id, ip)
        self._user_exists(user)
        if nick == user:
            raise BadRequest

        c = self.db.cursor()
        c.execute('''SELECT name FROM users
                     WHERE name = %s AND
                     (%s = ANY(friends::text[]) OR
                      %s = ANY(blacklist::text[]))''',
                  (user, nick, nick))
        if c.fetchone():
            raise BadRequest

        c.execute('''SELECT from_who FROM requests
                     WHERE from_who = %s AND to_who = %s OR
                     from_who = %s AND to_who = %s''', (user, nick,
                                                        nick, user))
        if c.fetchone():
            raise BadRequest

        with self.db:
            c.execute('''INSERT INTO requests
                         VALUES (%s, %s, %s)''', (nick, user, msg))

        c.close()
        return self._pack(sc.send_request_succ, request_id)

    def delete_profile(self, request_id, ip, session_id):
        """Удалить свой профиль"""
        nick = self._check_session(session_id, ip)
        nick_tuple = (nick,)
        c = self.db.cursor()
        c.execute('''SELECT friends::text[], dialogs::text[] FROM users
                     WHERE name = %s ''', nick_tuple)
        friends, messages = c.fetchone()

        c.execute('''DELETE FROM requests
                     WHERE from_who = %s OR to_who = %s''', nick_tuple * 2)

        self._close_session(session_id)

        for i in friends:
            self._remove_from(i, nick, 'friends')
            self._remove_from(i, nick, 'favorites')

        for i in messages:
            self._delete_dialog(int(i), nick)

        c.execute('''DELETE FROM profiles
                     WHERE name = %s''', nick_tuple)
        c.execute('''DELETE FROM users
                     WHERE name = %s''', nick_tuple)

        c.execute('''SELECT name FROM users''')
        for i in c.fetchall():
            self._remove_from(i['name'], nick, 'blacklist')

        self.db.commit()
        c.close()
        return self._pack(sc.delete_profile_succ, request_id)

    def logout(self, request_id, ip, session_id):
        """Выйти из системы"""
        self._check_session(session_id, ip)
        self._close_session(session_id)
        return self._pack(sc.logout_succ, request_id)

    def create_dialog(self, request_id, ip, session_id, user):
        """Создать диалог с пользователем user
        Вызывает BadRequest, если пользователь user
        не находится в друзьях отправителя"""
        nick = self._check_session(session_id, ip)
        self._user_exists(user)

        c = self.db.cursor()
        c.execute('''SELECT name FROM users
                     WHERE name = %s AND %s = ANY(friends::text[])''',
                  (user, nick))
        if not c.fetchone():
            raise BadRequest

        c.execute('''SELECT dialogs::text[] FROM users
                     WHERE name = %s OR name = %s''', (nick, user))
        dlg1 = set(c.fetchone()['dialogs'])
        dlg2 = set(c.fetchone()['dialogs'])

        if dlg1.intersection(dlg2):
            # Если у отправителя и пользователя user есть общий диалог
            return self._pack(sc.create_dialog_succ, request_id)

        d_st = str(self._next_free_dialog())
        with self.db:
            c.execute('''CREATE TABLE d{} (content text,
                                           timestamp bigint,
                                           sender text)'''.format(d_st))

        self._add_to(nick, d_st, 'dialogs')
        self._add_to(user, d_st, 'dialogs')

        c.close()
        return self._pack(sc.create_dialog_succ, request_id)

    def profile_info(self, request_id, ip, session_id, user):
        """Получить информацию о пользователе user
        Вызывает BadRequest, если отправитель находится
        в черном списке пользователя user"""
        nick = self._check_session(session_id, ip)
        self._user_exists(user)
        if self._is_blacklisted(nick, user):
            raise BadRequest
        c = self.db.cursor()
        c.execute('''SELECT status, email, birthday, about, image FROM profiles
                     WHERE name = %s''', (user,))

        *info, img_data = tuple(c.fetchone())

        c.close()
        return self._pack(sc.profile_info, request_id, *info) + b',' + bytes(img_data)

    def remove_from_blacklist(self, request_id, ip, session_id, user):
        """Удалить пользователя user из черного списка отправителя"""
        nick = self._check_session(session_id, ip)
        self._user_exists(user)
        self._remove_from(nick, user, 'blacklist')
        return self._pack(sc.remove_from_blacklist_succ, request_id)

    def take_request_back(self, request_id, ip, session_id, user):
        """Отменить запрос от отправителя к пользователю user"""
        nick = self._check_session(session_id, ip)
        self._user_exists(user)
        self._remove_add_request(nick, user)
        return self._pack(sc.take_request_back_succ, request_id)

    def confirm_add_request(self, request_id, ip, session_id, user):
        """Принять запрос на добавление от пользователя user отправителем
        Вызывает BadRequest, если пользователь user
        находится в черном списке отправителя"""
        nick = self._check_session(session_id, ip)
        self._user_exists(user)
        if self._is_blacklisted(user, nick):
            raise BadRequest
        self._remove_add_request(user, nick)
        self._add_to(user, nick, 'friends')
        self._add_to(nick, user, 'friends')
        return self._pack(sc.confirm_add_request_succ, request_id)

    def add_to_favorites(self, request_id, ip, session_id, user):
        """Добавить пользователя user в избранное отправителя
        Вызывает BadRequest, если пользователь user
        не находится в друзьях отправителя"""
        nick = self._check_session(session_id, ip)
        self._user_exists(user)

        c = self.db.cursor()
        c.execute('''SELECT name FROM users
                     WHERE name = %s AND %s = ANY(friends::text[])''',
                       (nick, user))
        if not c.fetchone():
            raise BadRequest
        self._add_to(nick, user, 'favorites')

        c.close()
        return self._pack(sc.add_to_favorites_succ, request_id)

    def delete_dialog(self, request_id, ip, session_id, dialog):
        """Удалить диалог под номером dialog от лица отправителя
        Вызывает BadRequest, если dialog не является целым числом"""
        nick = self._check_session(session_id, ip)
        if not isinstance(dialog, int):
            raise BadRequest
        self._user_in_dialog(nick, dialog)
        self._delete_dialog(dialog, nick)
        return self._pack(sc.delete_dialog_succ, request_id)

    def search_msg(self, request_id, ip, session_id, dialog, text, lower_tm, upper_tm):
        """Найти в диалоге под номером dialog сообщение,
        содержащее строку text и отправленное между
        временами lower_tm и upper_tm
        Вызывает BadRequest, если lower_tm > upper_tm"""
        if lower_tm > upper_tm:
            raise BadRequest
        nick = self._check_session(session_id, ip)
        self._user_in_dialog(nick, dialog)

        c = self.db.cursor()
        c.execute('''SELECT * FROM d{}
                     WHERE POSITION(%s IN content) > 0 AND
                     timestamp BETWEEN %s AND %s'''.format(dialog),
                  (text, lower_tm, upper_tm))
        result = map(tuple, c.fetchall())

        c.close()
        return self._pack(sc.search_msg_result, request_id, list(result))

    def remove_from_favorites(self, request_id, ip, session_id, user):
        """Удалить пользователя user из избранного отправителя"""
        nick = self._check_session(session_id, ip)
        self._user_exists(user)
        self._remove_from(nick, user, 'favorites')
        return self._pack(sc.remove_from_favorites_succ, request_id)

    def add_requests(self, request_id, ip, session_id):
        """Получить запросы на добавление к отправителю"""
        nick = self._check_session(session_id, ip)
        c = self.db.cursor()
        c.execute('''SELECT from_who, message FROM requests
                     WHERE to_who = %s''', (nick,))
        result = map(tuple, c.fetchall())
        c.close()
        return self._pack(sc.add_requests, request_id, list(result))

    def decline_add_request(self, request_id, ip, session_id, user):
        """Отменить запрос на добавление от пользователя user к отправителю"""
        nick = self._check_session(session_id, ip)
        self._user_exists(user)
        self._remove_add_request(user, nick)
        return self._pack(sc.decline_add_request_succ, request_id)

    def set_image(self, request_id, ip, session_id, img_data):
        """Установить в качестве изображения пользователя картинку,
        бинарные данные которой находятся в img_data"""
        nick = self._check_session(session_id, ip)
        c = self.db.cursor()
        with self.db:
            c.execute('''UPDATE profiles SET image = %s
                         WHERE name = %s''',
                      (img_data, nick))
        c.close()
        return self._pack(sc.set_image_succ, request_id)
