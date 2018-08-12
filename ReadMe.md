# RDS - Rootkit Detection System

My and [Daniel Cochavi] Software Engineering bachelor's degree final project.

Build for Windows 7 32bit.

This system will consist of five parts:
- Detection kernel mode driver application.
        - Kernel mode detection driver will scan the SSDT and kernel routines prologue for hooks.
- user mode detection dll.
        -  User mode detection dll will scan the IAT and relevant functions for hooks. 
- Two services that communicate and log the "Rootkit Detection System" activity.
        -  The services provide an interface to communicate between the kernel mode detection driver, 
user mode detection dll, and the UI. 
In addition, it potentially could send commands and provide logs from the kernel mode detection driver
and the user mode detection dll to the user.
- [APC dll injection driver] to inject the user mode dll to selected applications.
- A simple UI for follow-up with send commands to the "Rootkit Detection System" and to watch RDS information.



### system diagram

![alt text](https://github.com/0r13lc0ch4v1/Final_Project-R.D.S-Rootkit_Detection_System/blob/master/system_diagram.png)

![alt text](https://github.com/0r13lc0ch4v1/Final_Project-R.D.S-Rootkit_Detection_System/blob/master/DLL_diagram.png)

### Installation

We didn't make an installation package. You can deploy each component separately and use DbgView to see some logs.


### Todos

 - Extend to support other Windows versions.
 - In the driver change the IO method to [Direct IO].

License
----

MIT

### disclaimer 

We wrote this project for study purposes only as our degree final project. we don't write drivers, and this is our (more or less), the first driver we ever wrote. Along the way, we deleted and added code so it is not our best work, but still, we think it can help the community.

**Free Software, Hell Yeah!**

   [Daniel Cochavi]: <https://www.linkedin.com/in/danielcochavi/>
   [APC dll injection driver]: <https://github.com/0r13lc0ch4v1/APCInjector>
   [Direct IO]: <https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-direct-i-o>
