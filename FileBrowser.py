import argparse
import asyncio
import mimetypes
import os
import urllib.parse

STATUS_CODE = {
    '200': 'OK',
    '206': 'Partial Content',
    '404': 'Not Found',
    '405': 'Method Not Allowed'
}

response405 = [
    b'HTTP/1.0 405 Method Not Allowed\r\n',
    b'Content-Type:text/html; charset=utf-8\r\n',
    b'Connection: close\r\n',
    b'\r\n'
]

response404 = [
    b'HTTP/1.0 404 Not Found\r\n',
    b'Content-Type:text/html; charset=utf-8\r\n',
    b'Connection: close\r\n',
    b'\r\n'
]


class FileRequest:
    def __init__(self):
        self.start_line = {'method': '',
                           'path': '',
                           'http_version': '',
                           }
        self.header = {}

    def set_start_line(self, line: str):
        ary = line.split(' ')
        self.start_line['method'] = ary[0]
        self.start_line['path'] = ary[1]
        self.start_line['http_version'] = ary[2]

    def add_field_to_header(self, key: str, value: str):
        self.header[key.lower()] = value

    def get_header(self, key):
        try:
            return self.header[key]
        except KeyError:
            return None

    def get_start_line(self, key):
        return self.start_line[key]


class FileResponse:
    def __init__(self):
        self.start_line = {
            'http_version': '',
            'status_code': '',
            'description': ''
        }
        self.header = {
        }
        self.string = ''
        self.set_header('Connection', 'close')

    def set_start_line(self, http_version: str, status_code: str):
        self.start_line['http_version'] = http_version
        self.start_line['status_code'] = status_code
        self.start_line['description'] = STATUS_CODE[status_code]
        self.string += http_version + ' ' + status_code + ' ' + STATUS_CODE[status_code] + '\r\n'

    def get_start_line(self, key):
        return self.start_line[key]

    def set_header(self, key, value):
        self.header[key] = value

    def get_header(self, key):
        return self.header[key]

    def add_header_to_string(self):
        for k, v in self.header.items():
            self.string += str(k) + ': ' + str(v) + '\r\n'
        self.string += '\r\n'  # blank line

    def get_string(self):
        self.add_header_to_string()
        return self.string


async def dispatch(reader, writer):
    filereq = FileRequest()
    fileres = FileResponse()
    headline = True
    while True:
        data = await reader.readline()
        if data == b'\r\n':
            break
        message = data.decode().replace('\r\n', '')
        if headline:
            filereq.set_start_line(message)
            headline = False
        else:
            ary = message.split(': ')
            filereq.add_field_to_header(ary[0], ary[1])
    if filereq.get_start_line('method') == 'GET' or filereq.get_start_line('method') == 'HEAD':
        try:
            content = DO_GET_HEAD(filereq, fileres)
            writer.write(content)
        except FileNotFoundError:
            writer.writelines(response404)
    elif filereq.get_start_line('method') == 'POST':
        await asyncio.sleep(2)
        writer.writelines(response405)
    else:
        writer.writelines(response405)
    await writer.drain()
    writer.close()


def DO_GET_HEAD(filereq: FileRequest, fileres: FileResponse):
    path = '.' + filereq.get_start_line('path')
    body = b''
    if os.path.isdir(path):
        fileres.set_start_line('HTTP/1.0', '200')
        fileres.set_header('Content-Type', 'text/html; charset=utf-8')
        body = bytes(get_subdir_html(filereq), 'utf-8')
    else:  #
        #####
        if filereq.get_header('range') is not None:  # 206
            fileres.set_start_line('HTTP/1.0', '206')
            rag = filereq.get_header('range').split(',')[0].split('=')[1].replace(' ', '')
            ragtmp = rag.split('-')
            start = 0
            end = -1
            size = os.path.getsize('.' + filereq.get_start_line('path'))
            if not ragtmp[0]:
                # '-500'
                start = -500
                end = size-1
            else:
                start = int(ragtmp[0])
                if not ragtmp[1]:
                    # '500-'
                    end = int(size - 1)
                else:
                    # '499-500'
                    end = int(ragtmp[1])
            if start <= end:
                fileres.set_header('Content-Range', 'bytes %s-%s/%s' % (str(start), str(end), str(size)))
                body = display_file(filereq, fileres)[start:end + 1]
        else:
            fileres.set_start_line('HTTP/1.0', '200')
            body = display_file(filereq, fileres)
        fileres.set_header('Content-Length', len(body))
    if filereq.get_start_line('method') == 'GET':  # GET
        total = bytes(fileres.get_string(), 'utf-8') + body
    else:
        total = bytes(fileres.get_string(), 'utf-8')
    return total


def get_subdir_html(filereq: FileRequest) -> str:
    path = '.' + filereq.get_start_line('path')
    content = '<html><head><title>Index of %s</title></head>\r\n<body bgcolor="white">\r\n<h1>Index of %s</h1><hr>\r\n<pre>\r\n<a href="../">../</a><br>' % (
        path, path)
    tail = '</pre><hr></body></html>'
    subdir_list = os.listdir(path)
    for sl in subdir_list:
        sl_path = filereq.get_start_line('path') + '/' + sl
        if os.path.isdir('.' + sl_path):
            sl_path += '/'
        a_href = '<a href="%s">%s</a><br>' % (sl_path.replace("//", '/'), sl.replace("//", '/'))
        content += a_href
    content += tail
    return content


def display_file(filereq: FileRequest, fileres: FileResponse):
    path = '.' + filereq.get_start_line('path')
    path_parse = urllib.parse.unquote(path, 'utf-8')
    mime, _ = mimetypes.guess_type(path_parse)
    content = b''
    with open(path_parse, 'rb') as f:
        content = f.read()
    if mime is None:
        fileres.set_header('Content-Type', 'application/octet-stream')
    else:
        fileres.set_header('Content-Type', mime)
    return content


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple Web File Browser')
    parser.add_argument('--port', type=int, default=8080,
                        help='an integer for the port of the simple web file browser')
    parser.add_argument('--dir', type=str, default="./",
                        help='The Directory that the browser should display for home page')
    args = parser.parse_args()

    loop = asyncio.get_event_loop()
    os.chdir(args.dir)
    coro = asyncio.start_server(dispatch, '127.0.0.1', args.port, loop=loop)
    server = loop.run_until_complete(coro)
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
