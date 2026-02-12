# Py_xbdm
Py-xbdm is meant to be a replacement for XDevkit/JRPC_Client (PC side libraries for building RTE tools) for python.

- This is currently a work in progress
- I will provide further instructions and documentation soon
- I have include a basic example script to showcase a few of the features as well as an example UI using TKinter
- Figuring out the function calls was a pain but once I get the difficult stuff out of the way I will add more features
- This works from mobile devices using a python emulator

* Requirements:
  - Python (I'm using 3.9)
  - xbdm.xex set as a plugin on your console
  - JRPC2.xex set as a plugin on your console 

* Key features:
  - Basic console related info
  - Read/Write Memory
  - Function Calls (void, int, etc.)
  - Find available console Ip's (can connect without manually entering ip now)

* In Progress:
  - File Management
  - Miscellaneous missing functions/commands
  - Screenshots (working for Desktops, sorting out packaging issues for pypng on mobile devices)

<details>
  <summary>Images</summary> 
    # command line tool example
    <a href="https://gyazo.com/cc4427a1fe3110a284f14a1a1ffe23d9"><img src="https://i.gyazo.com/cc4427a1fe3110a284f14a1a1ffe23d9.png" alt="Image from Gyazo" width="1108"/></a>  
    # GUI example
    <a href="https://gyazo.com/3a7687c1ad069f47c3cea9268bc253bb"><img src="https://i.gyazo.com/3a7687c1ad069f47c3cea9268bc253bb.png" alt="Image from Gyazo" width="818"/></a>
</details>
