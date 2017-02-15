from tempfile import NamedTemporaryFile

from wsgiref.simple_server import make_server
from pyramid.config import Configurator
from pyramid.view import view_config

import os

@view_config(route_name="analyze", renderer="string")
def hello_world(request):
  import trueseeing.shell
  with NamedTemporaryFile('wb') as f:
    f.write(request.params['apk'].file.read())
    signatures_selected = trueseeing.shell.signatures_default.copy()
    return trueseeing.shell.processed(f.name, [v for k,v in trueseeing.shell.signatures.items() if k in signatures_selected], output_format='api')

if __name__ == '__main__':
  config = Configurator()
  # curl -X POST https://trueseeing.io/analyze -> ... -> (html)
  config.add_route('analyze', '/analyze')
  config.scan()
  app = config.make_wsgi_app()
  server = make_server('0.0.0.0', 9000, app)
  server.serve_forever()
