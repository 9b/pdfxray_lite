Summary
=======
PDF X-RAY is great, but there are times when all you have access to is a system you can't mess with, but need to do analysis on. PDF X-RAY Lite solves this by removing the backend and keeping it straight command line. For extra convenience a new reporting method is built into the malobjclass. This report switch allows you to get a bare-bones report so you can see the PDF in a visual form. Please note that this report is very basic and is only meant for reference.

Requirements
============
If you are running Ubuntu then you only need to grab the python-simplejson library for everything to work

Extending
=========
Located within pdfxray_lite.py is a section for "user code". Within this user code you can define anything you want and take advantage of the PDF python object or you can leave it blank and just use the report option.

Stripped Items
==============
- Backend database
- Entropy data
- Reporting engine
- API
