import json, logging, os
from installer import Installer
Installer().install()

from processors import Processor, cc, sc, BadRequest

from tornado.ioloop import IOLoop
from tornado.web import Application, RequestHandler as HTTPRequestHandler
from tornado.websocket import WebSocketHandler


class RequestHandler:
    pr = Processor()
    handler_map = {
        cc.register:                  pr.register,
        cc.login:                     pr.login,
        cc.search_username:           pr.search_username,
        cc.friends_group:             pr.friends_group,
        cc.get_message_history:       pr.message_history,
        cc.send_message:              pr.send_message,
        cc.change_profile_section:    pr.change_profile_section,
        cc.add_to_blacklist:          pr.add_to_blacklist,
        cc.delete_from_friends:       pr.delete_from_friends,
        cc.send_request:              pr.send_request,
        cc.delete_profile:            pr.delete_profile,
        cc.logout:                    pr.logout,
        cc.create_dialog:             pr.create_dialog,
        cc.get_profile_info:          pr.profile_info,
        cc.remove_from_blacklist:     pr.remove_from_blacklist,
        cc.take_request_back:         pr.take_request_back,
        cc.confirm_add_request:       pr.confirm_add_request,
        cc.add_to_favorites:          pr.add_to_favorites,
        cc.delete_dialog:             pr.delete_dialog,
        cc.search_msg:                pr.search_msg,
        cc.remove_from_favorites:     pr.remove_from_favorites,
        cc.get_add_requests:          pr.add_requests,
        cc.decline_add_request:       pr.decline_add_request,
        cc.set_image:                 pr.set_image,
    }
    set_image_code = str(cc.set_image).encode()
    profile_info_code = str(sc.profile_info).encode()

    o_codes = {cc.register, cc.login}
    t_codes = {cc.login,
               cc.send_message,
               cc.add_to_blacklist,
               cc.delete_from_friends,
               cc.send_request,
               cc.delete_profile,
               cc.logout,
               cc.remove_from_blacklist,
               cc.take_request_back,
               cc.confirm_add_request,
               cc.decline_add_request}

    connections = {}

    def unpack_req(self, request):
        """Распаковывает запрос request"""
        if request[:2] == self.set_image_code:
            comma_idx = 0
            for i in range(4):
                comma_idx += request[comma_idx:].find(b',') + 1
            body, img = request[:comma_idx - 1], request[comma_idx:]
            code, *data = json.loads('[' + body.decode() + ']')
            data.append(img)
            return code, data

        code, *data = json.loads('[' + request.decode() + ']')
        return code, data

    def unpack_resp(self, response):
        """Распаковывает ответ response"""
        if response[:2] == self.profile_info_code:
            comma_idx = 0
            for i in range(6):
                comma_idx += response[comma_idx:].find(b',') + 1
            body, img = response[:comma_idx - 1], response[comma_idx:]
            code, *data = json.loads('[' + body.decode() + ']')
            data.append(img)
            return code, data

        code, *data = json.loads('[' + response.decode() + ']')
        return code, data

    def process(self, enc_request, address, signature, enc_key):
        """Главный цикл работы сервера,
        отвечающий за обработку запросов"""
        log.info('received request from {}'.format(address))

        try:
            request = self.pr._decrypt(enc_request, enc_key)
            log.info('decrypted request successfully')
        except BadRequest:
            # Если расшифровать запрос не удалось, игнорируем
            log.error('failed to decrypt request')
            log.debug('request: {}'.format(request))
            return b''

        try:
            code, data = self.unpack_req(request)
        except ValueError:
            # Если распаковать запрос не удалось, игнорируем
            log.error('failed to decode request')
            log.debug('request: {}'.format(request))
            return b''

        is_o_request = code in self.o_codes
        if not is_o_request:
            if not signature:
                # Если подпись не указана, игнорируем
                log.error('no signature for an N/T-request')
                return b''

            try:
                pub_key = self.pr._get_public_key(address)
            except BadRequest:
                # Если нет сессии, открытой с IP-адреса address, игнорируем
                log.error('failed to get public key')
                return b''

            try:
                self.pr._verify_signature(enc_request, signature, pub_key)
            except BadRequest:
                # Если подпись неверная, игнорируем
                log.error('incorrect signature')
                return b''

        # Вставляем в запрос IP-адрес после ID запроса
        data.insert(1, address)

        try:
            # Выбор обработчика запроса, соответствующего его коду
            handler = self.handler_map[code]
            log.info('processing request with ' + handler.__name__ + '()')

            if code in self.t_codes:
                data.append(self.connections)

            # Запускаем обработчик и получаем ответ
            response = handler(*data)
        except (TypeError, IndexError, BadRequest):
            # Если в запросе логическая ошибка, игнорируем
            log.error('bad request from {}: {}'.format(address, request))
            return b''

        # Следующий блок кода может быть небезопасен
        r_code, r_data = self.unpack_resp(response)
        log.info('response code: ' + str(r_code))
        log.info('response data: ' + str(r_data))
        log.debug('response: {}'.format(response))

        if is_o_request:
            pub_key = self.pr._get_public_key(address)

        try:
            enc_response = self.pr._encrypt(response, pub_key)
        except OverflowError:
            log.error('server response was too large to encrypt')
            log.debug('response: {}'.format(response))
        log.info('encrypted response successfully')

        # Записываем текущую дату
        self.pr._set_timestamp(address)
        log.info('set new timestamp for: ' + address)

        log.info('sending reponse')
        return enc_response

    def get_key(self):
        return self.pr.pub_key_str


class Connector(WebSocketHandler):
    def initialize(self, handler):
        self.handler = handler

    def open(self):
        self._address = self.request.headers['X-Forwarded-For']

        if self._address in self.handler.connections:
            self.write_message('Connection refused')
            self.close()

        self.handler.connections[self._address] = self

    def on_message(self, message):
        enc_request, sign, enc_key = message.decode().split(':')
        resp = self.handler.process(enc_request, self._address, sign, enc_key)

        client_key = self.handler._get_public_key(self._address)
        enc_resp = self.handler._encrypt(resp, client_key)
        self.write_message(enc_resp, binary = True)


    def on_close(self):
        if self._address in self.handler.connections:
            self.handler.connections.pop(self._address)


class KeyHandler(HTTPRequestHandler):
    def initialize(self, handler):
        self.handler = handler

    def get(self):
        self.write(self.handler.get_key())


if __name__ == "__main__":
    log_level = logging.DEBUG

    log = logging.Logger('request_handler')
    log.setLevel(log_level)

    log_handler = logging.StreamHandler()
    log_handler.setLevel(log_level)

    log_fmt = logging.Formatter('[{asctime}] [{levelname}]\n{message}\n',
                                datefmt = '%d-%m %H:%M:%S', style = '{')
    log_handler.setFormatter(log_fmt)

    log.addHandler(log_handler)

    log.info('starting up')
    try:
        handler = RequestHandler()
        app = Application([(r'/', Connector, dict(handler = handler)),
                           (r'/key', KeyHandler, dict(handler = handler))])

        app.listen(os.getenv('PORT', 8080))

        IOLoop.current().start()
    except KeyboardInterrupt:
        log.info('manual exit')
    except Exception as e:
        log.exception('exception occured')
        log.critical('emergency exit')
