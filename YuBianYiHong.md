# AXL\_WITH\_DENYIP #

定义该宏可以使用 libantixunlei 自带的IP屏蔽函数。只需要实现定义好IP屏蔽的时间，然后只管屏蔽IP就行了。libantixunlei 会自动把到了解除屏蔽时间的IP从屏蔽列表中删除。

定义该宏以后就可以使用以下函数：

```
unsigned long ip2ulong(const char* ip);
int axl_ip_deny(unsigned long ip);
int axl_ip_denined(unsigned long ip);
```

# AXL\_WITH\_FORKSUPPORT #

在 Linux 下有不少服务器是以守护进程方式运行的，守护进程监听到连接请求后调用 fork() 产生一个子进程来处理请求。

由于 libantixunlei 要自己维护一个当前所有连接会话的表并管理相应的数据，而使用子进程来处理每一个连接的话就不能按照常规方法处理这些数据。所以，如果 FTP 服务器是以守护进程方式运行的话，编译 libantixunlei 时必须定义这个宏，好让 libantixunlei 知道必须使用非常规的方法来保管和维护会话数据。

# AXL\_WITH\_UNIIDSUPPORT #

某些 FTP 服务器不会给会话分配一个唯一标识，这样就不方便识别会话。定义该宏就可以使用 libantixunlei 的 axl\_uniid\_get() 函数来获得一个唯一的编号。