
How to run the Trustchain Crawler service
=========================================

This document is a short walkthrough to set up IPv8 and run Trustchain Crawler from scratch.

**Prerequisites**


#. Git is installed. If not, please check `here <https://git-scm.com/book/en/v2/Getting-Started-Installing-Git>`__.
#. Python2.7.9+ is installed. If not, please check `here <https://www.python.org/downloads/release/python-2715/>`__.
#. Python PIP is available in PATH and ``pip`` command is working.
#. PyCharm IDE (optional) if you want to make changes to the code. Download link `here <https://www.jetbrains.com/pycharm/download/>`__.

**Instructions**


#. 
   First you need to download  the ``py-ipv8`` source code from Github.

   .. code-block:: bash

       git clone https://github.com/tribler/py-ipv8.git

#. 
   Install the requirements for ``py-ipv8``.

   .. code-block:: bash

       cd py-ipv8
       pip install -r requirements.txt

#. 
   As we are running as a service, we require a few additional dependencies:
    a. `Install Libsodium <../preliminaries/install_libsodium.html>`_ 
    b. Yappi - a profiling tool

   .. code-block:: bash

       pip install yappi

#. 
   Now we are ready to run the Trustchain crawler. To run it, execute the following in the command line from
   within py-ipv8 directory. In Windows, use Git Bash instead of default command line.

   .. code-block:: bash

       export PYTHONPATH=.
       python scripts/trustchain_crawler_plugin.py

#. 
   The Trustchain crawler should now be running. To confirm, open the following URL in the browser:

   .. code-block:: none

       http://localhost:8085/trustchain/recent

   If the crawler service is working fine, you should be able to see the recent Trustchain blocks represented in JSON. 
   An example is shown below.

   .. code-block:: json

          {
           "blocks": [
               {
               "public_key": "4c69624e61434c504b3ab98b72619ffe33d77e0ba012c99c351f85f16ef75408b365bcb6a1504f7de84c579d5c8d3b61bd7909078e7b3baa32c90e4c2f91e9a823b2afb8feba2d63e653",
                   "transaction": {
                   "down": 0,
                   "total_down": 1870159641,
                   "up": 2537298,
                   "total_up": 11840925775
               },
               "hash": "75b1ad2b0dbdfe60e3c4fc35b5f836cb281bd8ff9396c78686e21b9d4d9513c6",
               "timestamp": 1547619629245,
               "link_public_key": "4c69624e61434c504b3aaf9ffc1ac1d2218428560606e7011767b0f99d10262f74ecae7ba7f3b7f2f4531e5b17f3805b9b495d985a8ee330c957ac464aec956072b49f4cb8e87b60fd3a",
               "type": "tribler_bandwidth",
               "insert_time": "2019-01-21 09:33:38",
               "signature": "314eb32bd5a8d49489e287e588795147a4def4e2ac066d12a48b416999cf69041d6dcf417faf8ee46ee339c745882e5ae276df102d2af73008f806ba73e1bd07",
               "previous_hash": "ffd0fb6b2ab633947dfde836d0fa37279c2bd8297b2769dc06a3fc4a9221b3c2",
               "link_sequence_number": 851,
               "sequence_number": 425
               },
               {
               "public_key": "4c69624e61434c504b3a669b77697b1092c377932362be5847732a002e8fdb09c52649c013d0cbbb457a8ee267e711576a59ff0310bbfd1fd49c801d841560688a163377f6089637ae4e",
               "transaction": {
                   "down": 0,
                   "total_down": 107140624998,
                   "up": 2152886,
                   "total_up": 1537265292586
               },
               "hash": "36a02c6a61d11ca924ad4cb11f58546af8ab1c840a014b182cad1fbe499b4014",
               "timestamp": 1547619040285,
               "link_public_key": "4c69624e61434c504b3aaf9ffc1ac1d2218428560606e7011767b0f99d10262f74ecae7ba7f3b7f2f4531e5b17f3805b9b495d985a8ee330c957ac464aec956072b49f4cb8e87b60fd3a",
               "type": "tribler_bandwidth",
               "insert_time": "2019-01-21 09:33:36",
               "signature": "2ef1bf3c5e4621df814c2970ea6e64acbf6bcb5c29670ea2a8ffdca5f1a85bce05460a7f6ebef58e34b65b2d989177c502a94effbd51467f80302557cf50900c",
               "previous_hash": "c0a42d3cd7dc29128e43c1be4182bc7a18133f6201c81416f6cd2929cb1cde5b",
               "link_sequence_number": 848,
               "sequence_number": 67260
               }
            ]
        }
