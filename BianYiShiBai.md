## pthread\_create 未定义 ##

这条错误也有可能是 pthread\_cancel 未定义。

打上下载中提供的 pureftpd 补丁后编译失败，这是因为 libantixunlei 使用了 pthread 线程库，在编译时需要指定连接 pthread 库，所以应该加上 -lpthread 编译参数。

解决方法有两个，一种是直接修改 Makefile，另一种是手动编译使用make编译失败的那个源码文件。手动编译方法如下：

  1. 执行 make，出错以后复制最后一条gcc编译指令；
  1. 进入 src 目录，粘贴刚才复制的命令，并在最后加上 -lpthread 参数，然后按下回车编译该文件；
  1. 退出 src 目录，继续执行 make。