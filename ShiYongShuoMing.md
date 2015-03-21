# 初始化和销毁 #

libantixunlei在使用前必须初始化，在 FTP 进程（仅守护进程）结束之前必须进行销毁操作。使用前请调用 axl\_init() 函数进行初始化，进程结束前请调用 axl\_destroy() 函数进行销毁。

# 识别迅雷 #

为了识别迅雷，需要向 libantixunlei 提供以下信息：

# 每一个会话的唯一标识：sess\_id
# 客户端发送给服务器的每一条FTP指令：cmd

在接收到客户端发送给服务器的指令后，调用 axl\_recive\_command(axl\_ftpcmd\_t cmd, unsigned long sess\_id) 函数告诉 libantixunlei 客户端发送了什么指令，调用结束后得到改函数的返回值 axl\_isxunlei\_t。

如果 axl\_recive\_command 返回值是 AXL\_ISXUNLEI\_YES，则可以明确地知道当前会话的客户端是迅雷，这时候就可以转入自己的处理函数，比如说是断开连接。

如果函数返回其他值，则请继续让FTP服务器处理该用户指令。

## axl\_recive\_command 函数的参数类型 ##

### axl\_isxunlei\_t ###
axl\_isxunlei\_t 是一个枚举类型（其实是一个整型），定义为以下三种取值：

```
#define AXL_ISXUNLEI_UNKNOWN            0
#define AXL_ISXUNLEI_YES                1
#define AXL_ISXUNLEI_NO                 2
```


### axl\_ftpcmd\_t ###
axl\_ftpcmd\_t 也是一个枚举类型，被定义为

```
#define AXL_FTPCMD_USER 1
#define AXL_FTPCMD_PASS 2
#define AXL_FTPCMD_CWD  3
#define AXL_FTPCMD_TYPE 4
#define AXL_FTPCMD_SIZE 5
#define AXL_FTPCMD_PASV 6
#define AXL_FTPCMD_REST 7
#define AXL_FTPCMD_RETR 8
/* 如果客户端发送的指令不属于以上几种指令，则将此指令认为是“其他”类型的指令，也就是下面那个指令 */
#define AXL_FTPCMD_OTHER 10
```

# 示例代码 #
```

int main(){
	// FTP服务器启动
	/*
	 * 你自己的FTP服务器的启动代码
	 * ...
	 */
	
	axl_init();	// 初始化libantixunlei
	
	/*
	 * FTP服务器已经正常启动，正在监听服务端口，并随时准备处理用户发送的指令
	 * 
	 * 你自己的FTP服务器代码 
	 * ... 
	 */

	/* 接收到客户端发送的FTP指令，char* cmd */
	if (axl_recive_command_string(cmd, sess_id) == AXL_ISXUNLEI_YES) {
		// 这家伙是迅雷，断开连接
		/**
		 * ftp_connect_close();
		 * 你自己的FTP服务器断开当前连接的代码 ...
		 */
	}
	else {
		// 这家伙不是迅雷，或者还不知道这家伙是不是迅雷，先处理这个指令
		/**
		 * ftp_process_command(cmd);
		 * 你自己的FTP服务器处理当前指令的代码 ...
		 */
	}
		
	// FTP服务器退出
	/*
	 * 你自己的FTP服务器结束代码
	 * ...
	 */
	
	
	return 0;
}

```



---


还有其他的一些API可以使用，但只需要上面三个函数就可以识别迅雷了，其他的API只是用于简化编程的，如 axl\_recive\_command\_string 等函数，这些函数的用法都写在源码中了，需要使用的话请查看源码。