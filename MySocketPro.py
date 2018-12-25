# encoding=utf-8

"""
    method <Space> from_who <CRLF>
    name[0] <Space> value[0] <CRLF>
    .....
    name[n] <Space> value[n] <CRLF>
    <CRLF>
    message
"""

"""
method:
    client ---> server:
        PUBLIC: 广播，发送给连接到服务器的每个客户端
        PRIVATE：私人消息，发送给特定的服务器，要求头部字段中有WITH字段，该字段值表示发送方的用户名
        
        LOGIN: 连接到客户端
        LOGINOUT： 退出
    server ---> client
        PRIVATE：私人消息，发送给特定的服务器，要求头部字段中有WITH字段，该字段值表示会话的另一方
        PUBLIC: 广播，发送给连接到服务器的每个客户端
        CLOSE: 服务器关闭
        UPDATE: 用于更新聊天室用户列表
        
        FULL: 服务器连接数达到上限
        USERILL: 用户名重复
        LOGIN: 登陆成功
from_who:
    发送方用户名
    
头部字段
    WITH: 私人聊天时，记录对话的用户
    
"""


# use for Server
def make_protocol_msg(method, from_who, message='', list = []):
    head = method + ' '
    head += from_who + '\n'
    if not list:
        for name, value in list:
            head += name + ' '
            head += value + '\n'
    head += '\n'
    protocol = head + message
    return protocol

def analyze_protocol_msg(data):
    # input: data --- message recieved, string
    # output: dict
    ret = {}
    index = data.find(' ')
    ret['method'] = data[0:index]
    data = data[index+1:]

    index = data.find('\n')
    ret['from_who'] = data[0:index]
    data = data[index+1:]

    while data != '' and data[0] != '\n':
        name = ''
        value = ''
        # get name
        index = data.find(' ')
        if index != -1:
            name = data[0:index]
            if len(data[index:]) > 1:
                data = data[index + 1:]
            else:
                data = ''
        else:
            break
        # get value
        index = data.find('\n')
        if index != -1:
            name = data[0:index]
            if len(data[index:]) > 1:
                data = data[index + 1:]
            else:
                data = ''
        else:
            print("the value of" + name + "not found!")
        ret[name] = value

    data = data[1:]
    while len(data) >= 1 and data[-1] == '\n':
        data = data[:len(data)-1]
    ret['message'] = data
    return ret

