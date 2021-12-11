# Publisher-Subscriber IPC Kernel Module
This project consists in the development of a kernel module for Linux systems that implements the **publisher-subscriber** design pattern for inter-processes communication. 

The module is the final result of _Advanced Operating Systems_ course in _Computer Science & Engineering Master Degree_ at Politecnico di Milano, Italy.

* Project supervisor: Federico Reghenzani
* Course head professor: Vittorio Zaccaria
* Student developers: [Ottavia Belotti](https://github.com/OttaviaBelotti) and [Riccardo Izzo](https://github.com/RiccardoIzzo)

## Module Injection
From terminal, run the given [Makefile](https://github.com/RiccardoIzzo/AOS-Publisher-Subscriber-IPC/blob/main/Makefile) in the project directory to compile the C source code into the `psipc_kmodule.ko` kernel object file.
```Shell
make
```

After compilation, to insert the module in the current system:
```Shell
#optional: clean the kernel message buffer before insertion
sudo dmesg -C
sudo insmod psipc_kmodule.ko
```

Once it is not needed anymore, remove it with:
```Shell
sudo rmmod psipc_kmodule
```

## Purpose of the project & How to use it
The module creates a tree-structure in the /dev directory that, once the module has been loaded succesfully, will resemble the one proposed below.
```Shell
/dev/psipc/
        |   
        |__ /new_topic
        |__ /topics
            |
            |__ /my_topic_1
            |   |
            |   |__ /subscribe
            |   |__ /subscribers_list
            |   |__ /signal_nr
            |   |__ /endpoint
            |
            |__ /my_topic_2
            .   |
            .   .
            .   .
```

A user process that acts as a publisher has to request the creation of the desired topic by writing its name on the `new_topic` file. The module creates a new directory in /dev/psipc/topics specific to that topic with all the necessary files related to it: `subscribe`, `subscribers_list`, `signal_nr` and `endpoint`.
Once this has been set up, other user processes running under the same user space as the creator of the topic can:
* __Subscribe to the topic__: write their PID in /subscribe. When a message is published for that topic, the subscriber will receive a signal (following POSIX standard), chosen by the publisher
* __Retrieve a list of all the subscribers__: read the /subscribers_list file to know the PIDs of all the processes currently subscribed to that topic
* __Read the published message__: read the last published message from /endpoint. This is allowed just for subscribed processes.

The publisher can:
* __Choose a signal__: choose a POSIX standard message by writing its number on /signal_nr file. Once the publisher write a new message, the signal will be sent to all the current subscribers of the topic. Writing more than once on /signal_nr overwrites the signal. If no signal is set, the module won't send anything to the subscribers. 
> _Note_: not setting a signal doesn't mean that the message can't be written. It just won't notify the subscribers.
* __Publish a message__: add a new message by writing it in /endpoint. If a signal has been set, the act of writing in here will notify the subscribers.
> _Note_: A publisher can't write a new message if all the present **notified** subscribers have not read the previous one yet.

## Development Environment
The module has been developed in **Ubuntu 20.04 LTS** distro with development tools on a Virtual Machine. 

Kernel version: v5.11
## Tools & Reference Material
* [The Linux Kernel Module Programming Guide](https://sysprog21.github.io/lkmpg/) - by Peter Jay Salzman, Michael Burian, Ori Pomerantz, Bob Mottram, Jim Huang
* [Linux](https://github.com/torvalds/linux) - Linus Torvalds official repository on GitHub
* [Bootlin Elixir Cross Referencer](https://elixir.bootlin.com/linux/v5.11.22/source) - to explore in an easier way the Linux source code
* [Oracle VM VirtualBox](https://www.virtualbox.org/)
