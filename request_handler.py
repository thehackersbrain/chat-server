import json, logging
from processors import Processor, cc, sc, BadRequest
from flask import Flask
from flask import request as flask_request
import os

app = Flask(__name__)

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
        cc.get_add_requests:          pr.add_requests,
        cc.decline_add_request:       pr.decline_add_request,
        cc.set_image:                 pr.set_image
    }
    set_image_code = str(cc.set_image.value).encode()
    profile_info_code = str(sc.profile_info.value).encode()

    @classmethod
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

    @classmethod
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

    @app.route('/', methods = ['GET', 'POST'])
    def process():
        """Главный цикл работы сервера,
        отвечающий за обработку запросов"""
        # Получение запроса
        address = flask_request.remote_addr
        request = flask_request.data
        print(flask_request.headers.getlist("X-Forwarded-For"))

        log.info('received request from {}'.format(address))
        log.debug('request: {}'.format(request))
        try:
            code, data = RequestHandler.unpack_req(request)
        except ValueError:
            # Если распаковать запрос не удалось, игнорируем
            log.error('failed to decode request {}'.format(request))
            return b''

        try:
            # Выбор обработчика запроса, руководствуясь его кодом
            handler = RequestHandler.handler_map[code]
            log.info('processing request with ' + handler.__name__ + '()')
            if address != data[1]:
                # Если IP-адрес, указанный в запросе, не совпадает с адресом,
                # откуда пришел запрос, игнорируем
                log.error('IP address in the request does not match the actual one')
                return b''

            # Запускаем обработчик и получаем ответ
            response = handler(*data)

        except (TypeError, IndexError, BadRequest):
            # Если в запросе логическая ошибка, игнорируем
            log.error('bad request from {}: {}'.format(address, request))
            return b''

        r_code, r_data = RequestHandler.unpack_resp(response)
        log.info('response code: ' + sc(r_code).name)
        log.info('response data: ' + str(r_data))
        log.debug('response: {}'.format(response))

        return str(response)

    @classmethod
    def run(self):
        app.run(debug=True, host=os.getenv('IP', '0.0.0.0'), port=int(os.getenv('PORT', 8080)))

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
    RequestHandler().run()
except KeyboardInterrupt:
    log.info('manual exit')
except Exception as e:
    log.exception('exception occured')
    log.critical('emergency exit')
