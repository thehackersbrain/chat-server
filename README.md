<img src="https://avatars3.githubusercontent.com/u/21263910?v=3&s=100" alt="MoarCatz logo"
     title="MoarCatz" align="right" />

[![Build Status](https://travis-ci.org/MoarCatz/chat-server.svg?branch=master)](https://travis-ci.org/MoarCatz/chat-server)
[![codecov](https://codecov.io/gh/MoarCatz/chat-server/branch/master/graph/badge.svg)](https://codecov.io/gh/MoarCatz/chat-server)

# Chat Server
Backend for the encrypted chat service.

## Getting Started
### Prerequisites
Here is a list of Python dependencies we're using right now:

* [Tornado](https://github.com/tornadoweb/tornado)
* [rsa](https://github.com/sybrenstuvel/python-rsa)
* [pyaes](https://github.com/ricmoo/pyaes)
* [psycopg2](https://github.com/psycopg/psycopg2)

### Deploying
Here is a step by step example of how you can get this server up and running:

#### Deploy to Heroku
Everything you need is to push the button below. You're welcome :smiley_cat:

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy)

#### Using The Source Code
Let's go through the terminal commands that will bring you to the running app:
```
git clone https://github.com/MoarCatz/chat-server.git  # Clone the code from Github
cd chat-server/
python3 installer.py  # Install the server
python3 request_handler.py  # Run
```

## Features
This server can:

* Receive requests from clients using WebSockets in realtime :zap:
* Decrypt and encrypt responses and replies :lock:
* Store the data in the database :file_folder:

## Contributing
We will be happy to see your PRs. If you can, please consider these topics we would also like to recieve help with:

- [ ] Asynchronous programming
- [ ] Testing
- [ ] Performance
- [ ] Security Issues

## License
This project is licensed under the GPL-3.0 License - see the [LICENSE](https://github.com/MoarCatz/chat-client/blob/master/LICENSE) file for details.

## Any Questions?
Shoot us a mail at chat@alexfox.co. We will be happy to meet you :sparkles:
