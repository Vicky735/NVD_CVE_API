# NVD_CVE_API
This project is a simple tool for automatic vulnerability recognition based on CVE identifiers using an API provided by the NVD.

## Features
It is a command-line interface program that provides a menu-based interface that allows you to interactively select options:
* CVE ID Extraction - it is one of the option in the menu that enables users to specify the path to a PDF file containing system scan results. The program then extracts CVE IDs from the PDF file using regular expressions. It displays the CVE IDs found in the file. Then, you can display ditails about those CVEs or save them to the txt file with the name you specify.
* If you choose option 2 from the menu, you can enter a specific CVE ID. The program retrieves vulnerability details for that CVE from the NVD API.  It displays information such as the CVE ID, source identifier, published date, last modified date, vulnerability status, description, weakness enumeration, and CVSS scores.
* The last option is to exit the program.
