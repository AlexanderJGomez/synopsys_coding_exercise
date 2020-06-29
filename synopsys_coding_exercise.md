Synopsys Black Duck KB Team Coding Exercise
--------

Overview
--------
**CVEs** (Common Vulnerabilities and Exposures) are an important and widespread tool used to communicate security vulnerabilities in software and hardware products, both open source and commercial.

The CVE system is operated by Mitre and CVEs are incorporated into the US government's National Vulnerability Database (**NVD**). NVD provides a *JSON* feed that provides modified CVE information on a moving-window basis.

That NVD JSON feed is the subject of this coding exercise.

Required Technologies
---------------------
- Python 3.5+
- PostgreSQL 9.6+
- git
- JSON

Directions
----------
Please complete this assignment and return it to us (see **Notes** section) within 3-4 days of receiving it. If you have any questions or require any clarification, please feel free to reach out to the contacts listed below.
- Research the NVD JSON feed listed below as well as using the link from the **Notes** section to become more familiar with its contents
- Pull *all* CVEs from https://nvd.nist.gov/vuln/data-feeds#JSON_FEED
    - Show that the list of CVEs and related data can be **efficiently** updated during the review
- Design a data model for the following in the JSON feed:
    - CVE ID
    - Description
    - CPE / Version ranges
    - Affected products on a version basis
    - Base CVSS score for both versions (when present)
    - Published Date
    - Last Modified Date
- Show **proficient** use of constraints, foreign keys and indices
- Be able to answer the following questions with live queries:
    - What are the top 10 most vulnerable products? (Based on the number of CVEs associated with them on a version basis.)
    - Show the breakdown of the number of CVEs per whole-number score (round up)

Notes
-----
- For more information about NVD, see https://nvd.nist.gov/home
- Feel free to use any open-source libraries that help complete the project
- If you have any command-line options, use the library **docopt**
- To interface with the Postgres database **psycopg2** is recommended 
- Include the Python code and the Database DDL in a **git** repo (commit early, commit often).

Submission
----------
Please include the archived repository containing the Python code and Database DDL sent via email to the contacts below by the discussed deadline.

This archive should include:
- All of the Python code required to run your crawler
- The Database DDL used to create your data model
- A **requirements.txt** file containing all open-source libraries used
- A **README** containing the queries used to answer the questions above in addition to instructions on running your code

Contacts
--------
- Josh Giangrande: <joshgi@synopsys.com>
- Stephen Andrews: <sandrews@synopsys.com>
- William Cox: <wcox@synopsys.com>
- Ken Hampson: <khampson@synopsys.com>