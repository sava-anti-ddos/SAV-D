.. SAVA Anti-DDoS documentation master file, created by
   sphinx-quickstart on Mon Feb  5 15:44:52 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. _sava-anti-ddos:

==============================
SAVA Anti-DDoS documentation!
==============================

Welcome to the SAVA Anti-DDoS documentation! This documentation is intended to provide a comprehensive guide to the SAVA Anti-DDoS system. 

Project Structure
=================

The project is structured as follows:

.. code-block:: bash

    ../src/
   ├── __init__.py
   ├── controller
   │   ├── __init__.py
   │   ├── config.ini
   │   ├── config.py
   │   ├── ddos_dectector.py
   │   ├── ip_blacklist.py
   │   ├── issue_rules.py
   │   ├── main.py
   │   ├── rule_generator.py
   │   ├── share_threat_information.py
   │   └── transport_server.py
   └── device
      ├── __init__.py
      ├── acl_helper.py
      ├── config.ini
      ├── config.py
      ├── main.py
      ├── monitor.py
      ├── packet_filter.py
      ├── receive_rule.py
      └── transport_client.py

.. toctree::
   :maxdepth: 2
   :caption: API Documentation

   src
   

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
