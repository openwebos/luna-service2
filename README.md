luna-service2
=============

Luna-service2 provides a bus-based IPC mechanism used between components in webOS. Luna-service2 is composed of a client library and a central hub daemon. The client library provides API support to register on the bus and communicate with other components. The hub provides a central clearinghouse for all communication. Utilities for monitoring and debugging the bus are included.

How to Build on Linux
=====================

## Dependencies

Below are the tools and libraries (and their minimum versions) required to build luna-service2:

* cmake 2.6
* gcc 4.3
* glib-2.0 2.16.6
* make (any version)
* openwebos/cjson 1.8.0
* openwebos/PmLogLib 2.0.0
* pkg-config 0.22


## Building

Once you have downloaded the source, execute the following to build it:

    $ mkdir BUILD
    $ cd BUILD
    $ cmake ..
    $ make
    $ sudo make install

The header files will be installed under

    /usr/local/include/luna-service2

the libraries and pkg-config file under

    /usr/local/lib

the daemon and utilities under

    /usr/local/bin

the configuration files under

    /usr/local/etc/ls2

and the upstart scripts under

    /usr/local/etc/event.d

You can install it elsewhere by supplying a value for _CMAKE\_INSTALL\_PREFIX_ when invoking _cmake_. For example:

    $ cmake -D CMAKE_INSTALL_PREFIX:STRING=$HOME/projects/openwebos ..
    $ make
    $ make install
    
will install the files in subdirectories of $HOME/projects/openwebos instead of subdirectories of /usr/local. 

Specifying _CMAKE\_INSTALL\_PREFIX_ also causes the pkg-config files under it to be used to find headers and libraries. To have _pkg-config_ look in a different tree, set the environment variable PKG_CONFIG_PATH to the path to its _lib/pkgconfig_ subdirectory.

## Generating documentation

The tools required to generate the documentation are:

* doxygen 1.6.3
* graphviz 2.20.2

Once you have run _cmake_, execute the following to generate the documentation:

    $ make docs

To view the generated HTML documentation, point your browser to

    doc/html/index.html

## Linking against luna-service2

If your system has pkgconfig then you can just add this to your makefile:

    CFLAGS += $(shell pkg-config --cflags luna-service2)
    LDFLAGS += $(shell pkg-config --libs luna-service2)

# Copyright and License Information

Unless otherwise specified, all content, including all source code files and
documentation files in this repository are:

Copyright (c) 2008-2012 Hewlett-Packard Development Company, L.P.

Unless otherwise specified or set forth in the NOTICE file, all content,
including all source code files and documentation files in this repository are:
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this content except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

