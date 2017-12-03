import socket
import string 

data = string.ascii_lowercase
MESSAGE = '{"id":1,"test":"' + data*100 + '"}\n'+'{"id":2,"cookie":"this will be deleted due to regex filter","test":"' + data*100 + '"}\n This rest is junk'

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect("testlb")
sock.send(MESSAGE)

