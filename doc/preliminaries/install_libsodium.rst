
Installing Libsodium (Windows and MacOS only)
=============================================

Running py-ipv8 on Windows or MacOS, requires manual installation of Libsodium.

Windows
-------


#. Libsodium can be downloaded from https://download.libsodium.org/libsodium/releases/  

   .. code-block:: console

        For eg. https://download.libsodium.org/libsodium/releases/libsodium-1.0.17-msvc.zip

#. Extract the files from the zip file
#. There are two extracted directories: ``x64`` and ``Win32``. Select ``x64`` for 64-bit or ``Win32`` for 32-bit versions of Windows, and search for ``libsodium.dll``. You can find one inside ``Release/v141/dynamic/libsodium.dll``
#. Copy this ``libsodium.dll`` file and paste it in ``C:\Windows\system32``

MacOS
-----

Homebrew can be used to install libsodium:

.. code-block:: bash

   brew install libsodium

For details, check `here <http://macappstore.org/libsodium/>`_.
