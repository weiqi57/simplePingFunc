%gcc ping-command.h ping-command.c -o pingCommand%

gcc ping-socket.h ping-socket.c -o pingSocket -lws2_32
%-lws2_32 表示windows平台编译需要链接Winsock库%