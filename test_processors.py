import unittest, time, rsa
from hashlib import sha256
from installer import Installer

Installer().install()
from processors import *
from request_handler import RequestHandler

class TestProcessor(unittest.TestCase):
    rh = RequestHandler()
    unpack = rh.unpack_resp

    pr = Processor()

    nick = 'test_user'
    ip = 'test_ip'
    pub_key, priv_key = rsa.newkeys(2048, accurate = False)
    pswd = sha256(b'pswdmysalt').hexdigest()
    request_id = '0'
    key_strings = list(map(str, pub_key.__getstate__()))

    def test__get_public_key(self):
        _get_public_key = self.pr._get_public_key
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)

        self.assertEqual(_get_public_key(self.ip), self.pub_key)

        self.pr._close_session(self.ip)
        with self.assertRaises(BadRequest):
            _get_public_key(self.ip)

    def test__decrypt(self):
        _decrypt = self.pr._decrypt
        c = self.pr.db.cursor()

        c.execute('''SELECT pub_key FROM key''')
        n, e = c.fetchone()['pub_key']
        server_pub = rsa.PublicKey(int(n), int(e))

        base = b'Hello, World'
        enc = rsa.encrypt(base, server_pub)
        self.assertEqual(_decrypt(enc), base)

        rand_bytes = b'not_encrypted'
        with self.assertRaises(BadRequest):
            _decrypt(rand_bytes)

        self.pr.db.commit()
        c.close()

    def test__encrypt(self):
        _encrypt = self.pr._encrypt

        base = b'Hello, World'
        enc = _encrypt(base, self.pub_key)
        self.assertEqual(rsa.decrypt(enc, self.priv_key), base)

    def test__verify_signature(self):
        _verify_signature = self.pr._verify_signature

        base = b'Hello, World'
        sign = rsa.sign(base, self.priv_key, 'SHA-256')
        _verify_signature(base, sign, self.pub_key)

        rand_bytes = b'not_a_signature'
        with self.assertRaises(BadRequest):
            _verify_signature(base, rand_bytes, self.pub_key)

    def test__add_session(self):
        _add_session = self.pr._add_session
        c = self.pr.db.cursor()

        _add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''SELECT * FROM sessions
                     WHERE name = %s AND pub_key = %s
                     AND ip = %s''', (self.nick, self.key_strings, self.ip))
        self.assertIsNotNone(c.fetchone())

        with self.assertRaises(BadRequest):
            _add_session(self.nick, ':'.join(self.key_strings), self.ip)

        self.pr._close_session(self.ip)
        self.pr.db.commit()
        c.close()

    def test__get_nick(self):
        _get_nick = self.pr._get_nick

        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)

        act_nick = _get_nick(self.ip)
        self.assertEqual(self.nick, act_nick)

        self.pr._close_session(self.ip)
        with self.assertRaises(BadRequest):
            _get_nick(self.ip)

    def test__pack(self):
        act1 = self.pr._pack('0', 1, [(2, 3), 4])
        exp1 = b'"0",1,[[2,3],4]'
        self.assertEqual(act1, exp1)

    def test__close_session(self):
        _close_session = self.pr._close_session
        c = self.pr.db.cursor()

        _close_session(self.ip)

        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''SELECT * FROM sessions
                     WHERE pub_key = %s''', (self.key_strings,))
        self.assertIsNotNone(c.fetchone())
        _close_session(self.ip)
        c.execute('''SELECT * FROM sessions
                     WHERE pub_key = %s''', (self.key_strings,))
        self.assertIsNone(c.fetchone())
        self.pr.db.commit()
        c.close()

    def test__remove_from(self):
        _remove_from = self.pr._remove_from
        c = self.pr.db.cursor()

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY['item'],
                                     ARRAY[]::text[],
                                     ARRAY['item1', 'item2'],
                                     ARRAY['1', '2', '3'])''',
                  (self.nick,))

        _remove_from(self.nick, 'item', 'friends')
        _remove_from(self.nick, 'item', 'favorites')
        _remove_from(self.nick, 'item1', 'blacklist')
        _remove_from(self.nick, '2', 'dialogs')

        c.execute('''SELECT friends::text[],
                            favorites::text[],
                            blacklist::text[],
                            dialogs::text[] FROM users
                     WHERE name = %s''', (self.nick,))
        row = tuple(c.fetchone())
        exp = ([], [], ['item2'], ['1', '3'])
        self.assertTupleEqual(row, exp)

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        self.pr.db.commit()
        with self.assertRaises(BadRequest):
            _remove_from(self.nick, 'item', 'friends')

        c.close()

    def test__is_blacklisted(self):
        _is_blacklisted = self.pr._is_blacklisted
        c = self.pr.db.cursor()

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY['user1', 'user2'],
                                     ARRAY[]::text[])''',
                  (self.nick,))

        self.assertTrue(_is_blacklisted('user1', self.nick))

        self.assertFalse(_is_blacklisted('user3', self.nick))

        self.assertFalse(_is_blacklisted(self.nick, self.nick))

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        self.assertFalse(_is_blacklisted('user1', self.nick))

        self.pr.db.commit()
        c.close()

    def test__remove_add_request(self):
        c = self.pr.db.cursor()
        _remove_add_request = self.pr._remove_add_request

        c.execute('''INSERT INTO requests
                     VALUES (%s, 'user', 'test request')''', (self.nick,))

        _remove_add_request(self.nick, 'user')
        _remove_add_request(self.nick, 'user')

        c.execute('''SELECT * FROM requests
                     WHERE from_who = %s AND to_who = 'user' ''',
                  (self.nick,))
        self.assertIsNone(c.fetchone())
        self.pr.db.commit()
        c.close()

    def test__add_to(self):
        _add_to = self.pr._add_to
        c = self.pr.db.cursor()

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY['item'],
                                     ARRAY[]::text[],
                                     ARRAY['item1' ,'item2'],
                                     ARRAY[]::text[])''',
                  (self.nick,))
        self.pr.db.commit()

        _add_to(self.nick, 'item3', 'friends')
        _add_to(self.nick, 'item4', 'blacklist')
        _add_to(self.nick, 'item2', 'blacklist')

        c.execute('''SELECT friends::text[], blacklist::text[]
                     FROM users WHERE name = %s''', (self.nick,))

        row = c.fetchone()
        self.assertEqual(row['friends'], ['item', 'item3'])
        self.assertEqual(row['blacklist'], ['item1', 'item2', 'item4'])

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))

        with self.assertRaises(BadRequest):
            _add_to(self.nick, 'item3', 'friends')

        self.pr.db.commit()
        c.close()

    def test__user_in_dialog(self):
        _user_in_dialog = self.pr._user_in_dialog
        c = self.pr.db.cursor()

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY['item'],
                                     ARRAY[]::text[],
                                     ARRAY['item1' ,'item2'],
                                     ARRAY['1', '2'])''', (self.nick,))

        _user_in_dialog(self.nick, 2)

        with self.assertRaises(BadRequest):
            _user_in_dialog(self.nick, '1')

        with self.assertRaises(BadRequest):
            _user_in_dialog(self.nick, 3)

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))

        with self.assertRaises(BadRequest):
            _user_in_dialog(self.nick, 3)

        self.pr.db.commit()
        c.close()

    def test__delete_dialog(self):
        _delete_dialog = self.pr._delete_dialog
        c = self.pr.db.cursor()
        user1 = '@first_user'
        user2 = '@other_user'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY['0', '1'])''', (self.nick,))

        msgs = ('', '', '', '')
        times = (0, 0, 0, 0)
        usrs = [(self.nick, user1) * 2,
                (self.nick, '~' + user1) * 2,
                (user1, user2) * 2]

        for i in range(3):
            c.execute('''CREATE TABLE "d{}" (content text,
                                             timestamp bigint,
                                             sender text)'''.format(i))
            c.executemany('''INSERT INTO "d{}"
                             VALUES (%s, %s, %s)'''.format(i),
                          zip(msgs, times, usrs[i]))

        _delete_dialog(0, self.nick)
        c.execute('''SELECT sender FROM "d0"''')
        senders = [i['sender'] for i in c.fetchall()]
        self.assertIn('~' + self.nick, senders)
        self.assertIn(user1, senders)

        _delete_dialog(1, self.nick)
        c.execute('''SELECT table_name FROM information_schema.tables
                     WHERE table_name = 'd1' AND table_schema = 'public' ''')
        self.assertIsNone(c.fetchone())

        _delete_dialog(2, self.nick)
        c.execute('''SELECT sender FROM "d2"''')
        senders = [i['sender'] for i in c.fetchall()]
        self.assertIn(user2, senders)
        self.assertIn(user1, senders)

        c.execute('''SELECT dialogs::text[] FROM users
                     WHERE name = %s''', (self.nick,))

        self.assertListEqual(c.fetchone()['dialogs'], [])

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        c.execute('''DROP TABLE "d0"''')
        c.execute('''DROP TABLE "d2"''')

        self.pr.db.commit()
        c.close()

    def test__user_exists(self):
        _user_exists = self.pr._user_exists
        c = self.pr.db.cursor()

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (self.nick,))

        _user_exists(self.nick)

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))

        with self.assertRaises(BadRequest):
            _user_exists(self.nick)

        c.close()

    def test__valid_nick(self):
        _valid_nick = self.pr._valid_nick

        self.assertTrue(_valid_nick(self.nick))

        self.assertFalse(_valid_nick('0' * 20))

        self.assertFalse(_valid_nick('~hacker'))

        self.assertTrue(_valid_nick('Test Nick'))
        self.assertFalse(_valid_nick(' ' * 5))

    def test__next_free_dialog(self):
        _nfd = self.pr._next_free_dialog
        c = self.pr.db.cursor()

        c.execute('''CREATE TABLE d0 (c int)''')
        c.execute('''CREATE TABLE d2 (c int)''')

        free1 = _nfd()
        self.assertEqual(free1, 1)

        c.execute('''CREATE TABLE d1 (c int)''')

        free2 = _nfd()
        self.assertEqual(free2, 3)

        for i in range(3):
            c.execute('''DROP TABLE d{}'''.format(i))

        self.pr.db.commit()
        c.close()

    def test_register(self):
        register = self.pr.register
        c = self.pr.db.cursor()

        resp1 = self.unpack(register(self.request_id,
                                     self.ip,
                                     self.nick,
                                     self.pswd,
                                     ':'.join(self.key_strings)))
        exp1 = (sc.register_succ,
                [self.request_id])
        self.assertTupleEqual(resp1, exp1)

        c.execute('''SELECT name, password, friends::text[],
                            favorites::text[], blacklist::text[],
                            dialogs::text[] FROM users
                     WHERE name = %s AND password = %s''',
                  (self.nick, self.pswd))
        self.assertTupleEqual(tuple(c.fetchone()),
                              (self.nick, self.pswd, [], [], [], [],))

        c.execute('''SELECT * FROM profiles
                     WHERE name = %s''', (self.nick,))
        self.assertTupleEqual(tuple(c.fetchone()),
                              (self.nick, '', '', 0, '', b''))

        resp2 = self.unpack(register(self.request_id,
                                     self.ip,
                                     self.nick,
                                     self.pswd,
                                     ':'.join(self.key_strings)))
        exp2 = (sc.register_error,
                [self.request_id])
        self.assertTupleEqual(resp2, exp2)

        resp3 = self.unpack(register(self.request_id,
                                     self.ip,
                                     '~' + self.nick,
                                     self.pswd,
                                     ':'.join(self.key_strings)))
        self.assertTupleEqual(resp3, exp2)

        c.execute('''DELETE FROM profiles
                     WHERE name = %s''', (self.nick,))
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        self.pr._close_session(self.ip)
        self.pr.db.commit()
        c.close()

    def test_login(self):
        login = self.pr.login
        c = self.pr.db.cursor()

        c.execute('''INSERT INTO users
                     VALUES (%s, %s, ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''',
                  (self.nick, self.pswd))

        resp1 = self.unpack(login(self.request_id,
                                  self.ip,
                                  self.nick,
                                  self.pswd,
                                  ':'.join(self.key_strings)))
        exp1 = (sc.login_succ,
                [self.request_id])
        self.assertEqual(resp1, exp1)

        resp2 = self.unpack(login(self.request_id,
                                  self.ip,
                                  self.nick,
                                  self.pswd,
                                  ':'.join(self.key_strings)))
        exp2 = (sc.login_error,
                [self.request_id])
        self.assertEqual(resp2, exp2)

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))

        resp3 = self.unpack(login(self.request_id,
                                  self.ip,
                                  self.nick,
                                  self.pswd,
                                  ':'.join(self.key_strings)))
        self.assertEqual(resp3, exp2)

        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_search_username(self):
        search_username = self.pr.search_username
        c = self.pr.db.cursor()

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (self.nick,))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        users = ('user1', 'user10', 'user2')
        for i in users:
            c.execute('''INSERT INTO users
                         VALUES (%s, '', ARRAY[]::text[],
                                         ARRAY[]::text[],
                                         ARRAY[]::text[],
                                         ARRAY[]::text[])''', (i,))

        resp1 = self.unpack(search_username(self.request_id,
                                            self.ip,
                                            'user1'))
        exp1 = (sc.search_username_result,
                [self.request_id,
                 ['user1', 'user10']])
        self.assertEqual(resp1[0], exp1[0])
        self.assertEqual(resp1[1][0], exp1[1][0])
        self.assertListEqual(sorted(resp1[1][1]), exp1[1][1])

        resp2 = self.unpack(search_username(self.request_id,
                                            self.ip,
                                            'user'))
        exp2 = (sc.search_username_result,
                [self.request_id,
                 [self.nick, 'user1', 'user10', 'user2']])
        self.assertEqual(resp2[0], exp2[0])
        self.assertEqual(resp1[1][0], exp1[1][0])
        self.assertListEqual(sorted(resp2[1][1]), exp2[1][1])

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        self.pr._close_session(self.ip)
        for i in users:
            c.execute('''DELETE FROM users
                         WHERE name = %s''', (i,))

        self.pr.db.commit()
        c.close()

    def test_friends_group(self):
        friends_group = self.pr.friends_group
        _add_session = self.pr._add_session
        _close_session = self.pr._close_session
        c = self.pr.db.cursor()

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY['user1', 'user10', 'user2'],
                                     ARRAY['user2'],
                                     ARRAY['user3'],
                                     ARRAY[]::text[])''', (self.nick,))
        _add_session(self.nick, ':'.join(self.key_strings), self.ip)
        users = ('user1', 'user10', 'user2', 'users3')
        for i in users:
            c.execute('''INSERT INTO users
                         VALUES (%s, '', ARRAY[]::text[],
                                         ARRAY[]::text[],
                                         ARRAY[]::text[],
                                         ARRAY[]::text[])''', (i,))
        _add_session('user1', '1:2', '1.1.1.1')
        _add_session('user2', '3:4', '2.2.2.2')

        resp = self.unpack(friends_group(self.request_id,
                                         self.ip))
        exp = (sc.friends_group_response,
               [self.request_id,
                [['user1', 'user2'],
                 ['user10'],
                 ['user2'],
                 ['user3']]])
        self.assertEqual(resp[0], exp[0])
        self.assertEqual(resp[1][0], exp[1][0])
        for i in range(len(resp[1][0])):
            self.assertListEqual(sorted(resp[1][1][i]), exp[1][1][i])

        _close_session(self.ip)
        _close_session('1.1.1.1')
        _close_session('2.2.2.2')
        for i in users:
            c.execute('''DELETE FROM users
                         WHERE name = %s''', (i,))
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))

        self.pr.db.commit()
        c.close()

    def test_message_history(self):
        message_history = self.pr.message_history
        c = self.pr.db.cursor()

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY['0'])''', (self.nick,))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''CREATE TABLE "d0" (content text,
                                        timestamp bigint,
                                        sender text)''')

        msgs = []
        for i in range(5):
            c.execute('''INSERT INTO "d0"
                         VALUES (%s, %s, %s)''', (str(i), 50 * i, self.nick))
            msgs.append([str(i), i * 50, self.nick])

        with self.assertRaises(BadRequest):
            message_history(self.request_id,
                            self.ip,
                            -1,
                            0)

        resp1 = self.unpack(message_history(self.request_id,
                                            self.ip,
                                            2,
                                            0))
        exp1 = (sc.message_history,
                [self.request_id, msgs[-2:]])
        self.assertTupleEqual(resp1, exp1)

        resp2 = self.unpack(message_history(self.request_id,
                                            self.ip,
                                            0,
                                            0))
        exp2 = (sc.message_history,
                [self.request_id, msgs])
        self.assertTupleEqual(resp2, exp2)

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        c.execute('''DROP TABLE "d0"''')
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_send_message(self):
        send_message = self.pr.send_message
        c = self.pr.db.cursor()
        other_user = '@other_user'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY['0'])''', (self.nick,))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''CREATE TABLE "d0" (content text,
                                        timestamp bigint,
                                        sender text)''')
        c.execute('''INSERT INTO "d0"
                     VALUES ('0', 0, %s)''', (self.nick,))
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[%s],
                                     ARRAY[]::text[])''',
                  (other_user, self.nick))

        msg_args = ['test', int(time.time() * 100), 0]
        resp1 = self.unpack(send_message(self.request_id,
                                         self.ip,
                                         *msg_args))
        exp1 = (sc.message_received,
                [self.request_id])
        self.assertTupleEqual(resp1, exp1)

        msg_args = msg_args[:2] + [self.nick]
        c.execute('''SELECT * FROM "d0"
                     WHERE content = %s AND timestamp = %s
                     AND sender = %s''', msg_args)
        self.assertIsNotNone(c.fetchone())

        with self.assertRaises(BadRequest):
            send_message(self.request_id,
                         self.ip,
                         '0' * 1001,
                         0,
                         self.nick)

        c.execute('''INSERT INTO "d0"
                     VALUES ('0', 0, %s)''', (other_user,))
        with self.assertRaises(BadRequest):
            send_message(self.request_id,
                         self.ip,
                         *msg_args)

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        c.execute('''DROP TABLE "d0"''')
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (other_user,))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_change_profile_section(self):
        change_profile_section = self.pr.change_profile_section
        c = self.pr.db.cursor()
        change = 'test'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (self.nick,))
        c.execute('''INSERT INTO profiles
                     VALUES (%s, '', '', 0, '', E'')''', (self.nick,))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)

        resp = self.unpack(change_profile_section(self.request_id,
                                                  self.ip,
                                                  0,
                                                  change))
        exp = (sc.change_profile_section_succ,
               [self.request_id])
        self.assertTupleEqual(resp, exp)

        c.execute('''SELECT * FROM profiles
                     WHERE name = %s''', (self.nick,))
        self.assertEqual(change, c.fetchone()['status'])

        with self.assertRaises(BadRequest):
            change_profile_section(self.request_id,
                                   self.ip,
                                   2,
                                   'not_int')

        with self.assertRaises(BadRequest):
            change_profile_section(self.request_id,
                                   self.ip,
                                   4,
                                   b'PNG')

        c.execute('''DELETE FROM profiles
                     WHERE name = %s''', (self.nick,))
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_add_to_blacklist(self):
        add_to_blacklist = self.pr.add_to_blacklist
        c = self.pr.db.cursor()
        user1 = '@other_user'
        user2 = '@first_user'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[%s],
                                     ARRAY[%s],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''',
                  (self.nick, user1, user1))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (user1,))
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (user2,))
        c.execute('''INSERT INTO requests
                     VALUES (%s, %s, '')''', (self.nick, user2))

        resp = self.unpack(add_to_blacklist(self.request_id,
                                            self.ip,
                                            user1))
        exp = (sc.add_to_blacklist_succ,
               [self.request_id])
        self.assertTupleEqual(resp, exp)

        add_to_blacklist(self.request_id,
                         self.ip,
                         user2)

        with self.assertRaises(BadRequest):
            add_to_blacklist(self.request_id,
                             self.ip,
                             self.nick)

        c.execute('''SELECT friends::text[],
                            favorites::text[],
                            blacklist::text[] FROM users
                     WHERE name = %s''', (self.nick,))
        row = c.fetchone()
        self.assertListEqual(row['friends'], [])
        self.assertListEqual(row['favorites'], [])
        self.assertListEqual(row['blacklist'], [user1, user2])

        c.execute('''SELECT * FROM requests
                     WHERE from_who = %s AND to_who = %s''',
                  (self.nick, user2))
        self.assertIsNone(c.fetchone())

        c.execute('''DELETE FROM users
                     WHERE name = %s OR name = %s
                     OR name = %s''', (self.nick, user1, user2))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_delete_from_friends(self):
        delete_from_friends = self.pr.delete_from_friends
        c = self.pr.db.cursor()
        user1 = '@other_user'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[%s],
                                     ARRAY[%s],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''',
                  (self.nick, user1, user1))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (user1,))

        resp = self.unpack(delete_from_friends(self.request_id,
                                           self.ip,
                                           user1))
        exp = (sc.delete_from_friends_succ,
               [self.request_id])
        self.assertTupleEqual(resp, exp)

        c.execute('''SELECT friends::text[],
                            favorites::text[] FROM users
                     WHERE name = %s''', (self.nick,))
        row = c.fetchone()
        self.assertListEqual(row['friends'], [])
        self.assertListEqual(row['favorites'], [])

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (user1,))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_send_request(self):
        send_request = self.pr.send_request
        c = self.pr.db.cursor()
        user1 = '@other_user'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (self.nick,))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (user1,))

        resp = self.unpack(send_request(self.request_id,
                                        self.ip,
                                        user1,
                                        ''))
        exp = (sc.send_request_succ,
               [self.request_id])
        self.assertTupleEqual(resp, exp)

        c.execute('''SELECT * FROM requests
                     WHERE from_who = %s AND to_who = %s
                     AND message = '' ''', (self.nick, user1))
        self.assertIsNotNone(c.fetchone())

        with self.assertRaises(BadRequest):
            send_request(self.request_id,
                         self.ip,
                         user1,
                         '')

        c.execute('''DELETE FROM requests
                     WHERE from_who = %s AND to_who = %s''',
                  (self.nick, user1))

        self.pr._add_to(user1, self.nick, 'friends')
        with self.assertRaises(BadRequest):
            send_request(self.request_id,
                         self.ip,
                         user1,
                         '')

        self.pr._remove_from(user1, self.nick, 'friends')
        self.pr._add_to(user1, self.nick, 'friends')
        with self.assertRaises(BadRequest):
            send_request(self.request_id,
                         self.ip,
                         user1,
                         '')

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (user1,))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_delete_profile(self):
        delete_profile = self.pr.delete_profile
        c = self.pr.db.cursor()
        user1 = '@other_user'
        user2 = '@first_user'
        user3 = '@second_user'
        user4 = '@last_user'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[%s],
                                     ARRAY[%s],
                                     ARRAY[]::text[],
                                     ARRAY['0'])''',
                  (self.nick, user1, user1))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''INSERT INTO profiles
                     VALUES (%s, '', '', 0, '', E'')''', (self.nick,))
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[%s],
                                     ARRAY[%s],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''',
                  (user1, self.nick, self.nick))
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[%s],
                                     ARRAY[]::text[])''', (user2, self.nick))
        c.execute('''CREATE TABLE "d0" (content text,
                                        timestamp bigint,
                                        sender text)''')
        c.execute('''INSERT INTO "d0"
                     VALUES ('', 0, %s)''', (self.nick,))
        c.execute('''INSERT INTO requests
                     VALUES (%s, %s, '')''', (user3, self.nick))
        c.execute('''INSERT INTO requests
                     VALUES (%s, %s, '')''', (self.nick, user4))

        resp = self.unpack(delete_profile(self.request_id,
                                          self.ip))
        exp = (sc.delete_profile_succ,
               [self.request_id])
        self.assertTupleEqual(resp, exp)

        c.execute('''SELECT * FROM users
                     WHERE name = %s''', (self.nick,))
        self.assertIsNone(c.fetchone())

        c.execute('''SELECT * FROM profiles
                     WHERE name = %s''', (self.nick,))
        self.assertIsNone(c.fetchone())

        c.execute('''SELECT friends::text[],
                            favorites::text[] FROM users
                     WHERE name = %s''', (user1,))
        for i in c.fetchone():
            self.assertListEqual(i, [])

        c.execute('''SELECT blacklist::text[] FROM users
                     WHERE name = %s''', (user2,))
        self.assertListEqual(c.fetchone()['blacklist'], [])

        c.execute('''SELECT table_name FROM information_schema.tables
                     WHERE table_name = 'd0' and table_schema = 'public' ''')
        self.assertIsNone(c.fetchone())

        c.execute('''SELECT * FROM requests
                     WHERE from_who = %s OR to_who = %s''',
                  (self.nick, self.nick))
        self.assertListEqual(c.fetchall(), [])

        c.execute('''SELECT name FROM sessions
                     WHERE ip = %s''', (self.ip,))
        self.assertIsNone(c.fetchone())

        self.pr._close_session(self.ip)
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (user1,))
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (user2,))

        self.pr.db.commit()
        c.close()

    def test_logout(self):
        logout = self.pr.logout
        c = self.pr.db.cursor()

        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)

        resp = self.unpack(logout(self.request_id,
                                  self.ip))
        exp = (sc.logout_succ,
               [self.request_id])
        self.assertTupleEqual(resp, exp)

        c.execute('''SELECT * FROM sessions
                     WHERE ip = %s''', (self.ip,))
        self.assertIsNone(c.fetchone())

        self.pr.db.commit()

    def test_create_dialog(self):
        create_dialog = self.pr.create_dialog
        c = self.pr.db.cursor()
        user1 = '@other_user'
        user2 = '@first_user'
        user3 = '@second_user'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[%s],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY['0'])''',
                  (self.nick, user1 + ',' + user2))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[%s],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (user1, self.nick))
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[%s],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY['0'])''', (user2, self.nick))
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (user3,))
        c.execute('''CREATE TABLE "d0" (content text,
                                        timestamp bigint,
                                        sender text)''')

        resp = self.unpack(create_dialog(self.request_id,
                                         self.ip,
                                         user1))
        exp = (sc.create_dialog_succ,
               [self.request_id])
        self.assertTupleEqual(resp, exp)

        create_dialog(self.request_id,
                      self.ip,
                      user2)
        c.execute('''SELECT dialogs::text[] FROM users
                     WHERE name = %s''', (user1,))
        dlg1 = c.fetchone()['dialogs']
        c.execute('''SELECT dialogs::text[] FROM users
                     WHERE name = %s''', (user2,))
        dlg2 = c.fetchone()['dialogs']
        c.execute('''SELECT dialogs::text[] FROM users
                     WHERE name = %s''', (self.nick,))
        dlg_main = c.fetchone()['dialogs']
        self.assertListEqual(dlg_main, dlg2 + dlg1)

        dlg1_name = 'd' + str(dlg1[0])
        dlg2_name = 'd' + str(dlg2[0])

        c.execute('''SELECT table_name FROM information_schema.tables
                     WHERE table_name = %s OR table_name = %s
                     AND table_schema = 'public' ''',
                  (dlg1_name, dlg2_name))
        self.assertEqual(len(c.fetchall()), 2)

        with self.assertRaises(BadRequest):
            create_dialog(self.request_id,
                          self.ip,
                          user3)

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (user1,))
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (user2,))
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (user3,))
        c.execute('''DROP TABLE "d0"''')
        c.execute('''DROP TABLE "{}"'''.format(dlg1_name))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_profile_info(self):
        profile_info = self.pr.profile_info
        c = self.pr.db.cursor()
        status = 'status'
        email = 'email'
        user1 = '@other_user'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (self.nick,))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''INSERT INTO profiles
                     VALUES (%s, %s, %s, 0, '', E'')''',
                  (self.nick, status, email))
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[%s],
                                     ARRAY[]::text[])''', (user1, self.nick))

        resp = self.unpack(profile_info(self.request_id,
                                        self.ip,
                                        self.nick))
        exp = (sc.profile_info,
               [self.request_id,
                status,
                email,
                0,
                '',
                b''])
        self.assertEqual(resp, exp)

        with self.assertRaises(BadRequest):
            profile_info(self.request_id,
                         self.ip,
                         user1)

        c.execute('''DELETE FROM profiles
                     WHERE name = %s''', (self.nick,))
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (user1,))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_remove_from_blacklist(self):
        remove_from_blacklist = self.pr.remove_from_blacklist
        c = self.pr.db.cursor()
        user1 = '@other_user'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[%s],
                                     ARRAY[]::text[])''', (self.nick, user1))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (user1,))

        resp = self.unpack(remove_from_blacklist(self.request_id,
                                                 self.ip,
                                                 user1))
        exp = (sc.remove_from_blacklist_succ,
               [self.request_id])
        self.assertTupleEqual(resp, exp)

        c.execute('''SELECT blacklist::text[] FROM users
                     WHERE name = %s''', (self.nick,))
        self.assertListEqual(c.fetchone()['blacklist'], [])

        c.execute('''DELETE FROM users
                     WHERE name = %s OR name = %s''', (self.nick, user1))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_take_request_back(self):
        take_request_back = self.pr.take_request_back
        c = self.pr.db.cursor()
        user1 = '@other_user'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (self.nick,))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (user1,))
        c.execute('''INSERT INTO requests
                     VALUES (%s, %s, '')''', (self.nick, user1))

        resp = self.unpack(take_request_back(self.request_id,
                                             self.ip,
                                             user1))
        exp = (sc.take_request_back_succ,
               [self.request_id])
        self.assertTupleEqual(resp, exp)

        c.execute('''SELECT * FROM requests
                     WHERE from_who = %s AND to_who = %s''',
                  (self.nick, user1))
        self.assertIsNone(c.fetchone())

        c.execute('''DELETE FROM users
                     WHERE name = %s OR name = %s''', (self.nick, user1))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_confirm_add_request(self):
        confirm_add_request = self.pr.confirm_add_request
        c = self.pr.db.cursor()
        user1 = '@other_user'
        user2 = '@first_user'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[%s],
                                     ARRAY[]::text[])''', (self.nick, user2))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (user1,))
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (user2,))
        c.execute('''INSERT INTO requests
                     VALUES (%s, %s, '')''', (user1, self.nick))
        c.execute('''INSERT INTO requests
                     VALUES (%s, %s, '')''', (user2, self.nick))

        resp = self.unpack(confirm_add_request(self.request_id,
                                               self.ip,
                                               user1))
        exp = (sc.confirm_add_request_succ,
               [self.request_id])
        self.assertTupleEqual(resp, exp)

        c.execute('''SELECT friends::text[] FROM users
                     WHERE name = %s''', (user1,))
        fr1 = c.fetchone()['friends']
        self.assertListEqual(fr1, [self.nick])

        c.execute('''SELECT friends::text[] FROM users
                     WHERE name = %s''', (self.nick,))
        fr_main = c.fetchone()['friends']
        self.assertListEqual(fr_main, [user1])

        c.execute('''SELECT * FROM requests
                     WHERE from_who = %s AND to_who = %s''',
                  (user1, self.nick))
        self.assertIsNone(c.fetchone())

        with self.assertRaises(BadRequest):
            confirm_add_request(self.request_id,
                                self.ip,
                                user2)

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (user1,))
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (user2,))
        c.execute('''DELETE FROM requests
                     WHERE from_who = %s''', (user2,))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_add_to_favorites(self):
        add_to_favorites = self.pr.add_to_favorites
        c = self.pr.db.cursor()
        user1 = '@other_user'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[%s],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (self.nick, user1))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[%s],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (user1, self.nick))

        resp = self.unpack(add_to_favorites(self.request_id,
                                            self.ip,
                                            user1))
        exp = (sc.add_to_favorites_succ,
               [self.request_id])
        self.assertTupleEqual(resp, exp)

        c.execute('''SELECT favorites::text[] FROM users
                     WHERE name = %s''', (self.nick,))
        self.assertListEqual(c.fetchone()['favorites'], [user1])

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (user1,))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_delete_dialog(self):
        delete_dialog = self.pr.delete_dialog
        c = self.pr.db.cursor()

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY['0'])''', (self.nick,))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''CREATE TABLE "d0" (content text,
                                        timestamp bigint,
                                        sender text)''')
        c.execute('''INSERT INTO "d0"
                     VALUES ('', 0, %s)''', (self.nick,))

        resp = self.unpack(delete_dialog(self.request_id,
                                         self.ip,
                                         0))
        exp = (sc.delete_dialog_succ,
               [self.request_id])
        self.assertTupleEqual(resp, exp)

        c.execute('''SELECT table_name FROM information_schema.tables
                     WHERE table_name = 'd0' AND table_schema = 'public' ''')
        self.assertIsNone(c.fetchone())

        with self.assertRaises(BadRequest):
            delete_dialog(self.request_id,
                          self.ip,
                          'not_int')

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_search_msg(self):
        search_msg = self.pr.search_msg
        c = self.pr.db.cursor()
        messages = [['test_message', 50, self.nick],
                    ['different', 60, self.nick],
                    ['look here', 70, self.nick],
                    ['more text', 80, self.nick],
                    ['look above', 90, self.nick],
                    ['nothing to see', 100, self.nick]]

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY['0'])''', (self.nick,))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''CREATE TABLE "d0" (content text,
                                        timestamp bigint,
                                        sender text)''')
        c.executemany('''INSERT INTO "d0"
                         VALUES (%s, %s, %s)''', messages)

        resp1 = self.unpack(search_msg(self.request_id,
                                       self.ip,
                                       0,
                                       'test_mess',
                                       50,
                                       100))
        exp1 = (sc.search_msg_result,
                [self.request_id,
                 [messages[0]]])
        self.assertTupleEqual(resp1, exp1)

        resp2 = self.unpack(search_msg(self.request_id,
                                       self.ip,
                                       0,
                                       'look',
                                       50,
                                       80))
        exp2 = (sc.search_msg_result,
                [self.request_id,
                 [messages[2]]])
        self.assertTupleEqual(resp2, exp2)

        resp3 = self.unpack(search_msg(self.request_id,
                                       self.ip,
                                       0,
                                       'look nowhere',
                                       0,
                                       100))
        exp3 = (sc.search_msg_result,
                [self.request_id,
                 []])
        self.assertTupleEqual(resp3, exp3)

        with self.assertRaises(BadRequest):
            search_msg(self.request_id,
                       self.ip,
                       0,
                       'smth',
                       100,
                       0)

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        c.execute('''DROP TABLE "d0"''')
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_remove_from_favorites(self):
        remove_from_favorites = self.pr.remove_from_favorites
        c = self.pr.db.cursor()
        user1 = '@other_user'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[%s],
                                     ARRAY[%s],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''',
                  (self.nick, user1, user1))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[%s],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (user1, self.nick))

        resp = self.unpack(remove_from_favorites(self.request_id,
                                                 self.ip,
                                                 user1))
        exp = (sc.remove_from_favorites_succ,
               [self.request_id])
        self.assertTupleEqual(resp, exp)

        c.execute('''SELECT friends::text[],
                            favorites::text[] FROM users
                     WHERE name = %s''', (self.nick,))
        row = c.fetchone()
        self.assertEqual(row['favorites'], [])
        self.assertEqual(row['friends'], [user1])

        c.execute('''DELETE FROM users
                     WHERE name = %s OR name = %s''', (self.nick, user1))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_add_requests(self):
        add_requests = self.pr.add_requests
        c = self.pr.db.cursor()
        user1 = '@other_user'
        user2 = '@first_user'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (self.nick,))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''INSERT INTO requests
                     VALUES (%s, %s, 'hello')''', (user1, self.nick))
        c.execute('''INSERT INTO requests
                     VALUES (%s, %s, 'wrong')''', (user1, user2))

        resp = self.unpack(add_requests(self.request_id,
                                        self.ip))
        exp = (sc.add_requests,
               [self.request_id,
                [[user1, 'hello']]])
        self.assertTupleEqual(resp, exp)

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        c.execute('''DELETE FROM requests
                     WHERE from_who = %s''', (user1,))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_decline_add_request(self):
        decline_add_request = self.pr.decline_add_request
        c = self.pr.db.cursor()
        user1 = '@other_user'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (self.nick,))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)
        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (user1,))
        c.execute('''INSERT INTO requests
                     VALUES (%s, %s, '')''', (user1, self.nick))

        resp = self.unpack(decline_add_request(self.request_id,
                                               self.ip,
                                               user1))
        exp = (sc.decline_add_request_succ,
               [self.request_id])
        self.assertTupleEqual(resp, exp)

        c.execute('''SELECT * FROM requests
                     WHERE from_who = %s AND to_who = %s''',
                  (user1, self.nick))
        self.assertIsNone(c.fetchone())

        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (user1,))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_set_image(self):
        set_image = self.pr.set_image
        c = self.pr.db.cursor()
        img = b'PNG'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[])''', (self.nick,))
        c.execute('''INSERT INTO profiles
                     VALUES (%s, '', '', 0, '', E'')''', (self.nick,))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)

        resp = self.unpack(set_image(self.request_id,
                                     self.ip,
                                     img))
        exp = (sc.set_image_succ,
               [self.request_id])
        self.assertTupleEqual(resp, exp)

        c.execute('''SELECT image FROM profiles
                     WHERE name = %s''', (self.nick,))
        self.assertEqual(bytes(c.fetchone()['image']), img)

        c.execute('''DELETE FROM profiles
                     WHERE name = %s''', (self.nick,))
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

    def test_get_dialogs(self):
        get_dialogs = self.pr.get_dialogs
        c = self.pr.db.cursor()
        user1 = '@other_user'
        user2 = '@first_user'

        c.execute('''INSERT INTO users
                     VALUES (%s, '', ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY[]::text[],
                                     ARRAY['0', '1'])''', (self.nick,))
        self.pr._add_session(self.nick, ':'.join(self.key_strings), self.ip)

        c.execute('''CREATE TABLE "d0" (content text,
                                        timestamp bigint,
                                        sender text)''')
        c.execute('''CREATE TABLE "d1" (content text,
                                        timestamp bigint,
                                        sender text)''')
        c.execute('''INSERT INTO "d0"
                     VALUES ('test', 0, %s)''', (user1,))
        c.execute('''INSERT INTO "d1"
                     VALUES ('test', 0, %s)''', (user2,))

        resp = self.unpack(get_dialogs(self.request_id,
                                       self.ip))
        exp = (sc.get_dialogs_resp,
               [self.request_id,
                [['0', user1],
                 ['1', user2]]])
        self.assertTupleEqual(resp, exp)

        c.execute('''DROP TABLE "d0"''')
        c.execute('''DROP TABLE "d1"''')
        c.execute('''DELETE FROM users
                     WHERE name = %s''', (self.nick,))
        self.pr._close_session(self.ip)

        self.pr.db.commit()
        c.close()

if __name__ == '__main__':
    unittest.main()

