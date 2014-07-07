Requirements
============
1. development package of pidgin and libpurple
#. osxcart (http://sourceforge.net/projects/osxcart/)

Building
========
::

	make

Installation
============
::

	make install

Which copies the plugin to ~/.purple/plugins/

Ubuntu Example
==============
::

	sudo apt-get install pidgin-dev libpth-dev

and then install the osxcart from http://sourceforge.net/projects/osxcart/
::

	make
	make install
  sudo ln -s /usr/local/lib/libosxcart.so.0 /usr/lib/libosxcart.so.0
