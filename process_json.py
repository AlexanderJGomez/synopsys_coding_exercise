import psycopg2
import json
import requests
import re
from os import path
from dateutil.parser import parse
import zipfile
from io import BytesIO
from cpe.cpe2_3_fs import CPE2_3_FS
import time
from datetime import timedelta, datetime as dt


# CONSTANTS

DB_CONFIG_FILE = "db_config.json"

YEAR_RANGE = range(2002, 2021)
CVE_ZIP_URL_TEMPLATE = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.zip"
CVE_JSON_FILE_TEMPLATE = "nvdcve-1.1-%s.json"
CVE_ID_RE = re.compile('CVE-(\d*)-(\d*)')

MODIFIED_METAFILE_PATH = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta"
LAST_UPDATE_FILE = "last_update.txt"
LAST_MODIFIED_DATE_FORMAT ='%Y-%m-%dT%H:%M:%S-04:00'
UPDATE_INTERVAL = 1  # The minimum minutes time difference to update


VERSION_START_EXCLUDING = "versionStartExcluding"
VERSION_START_INCLUDING = "versionStartIncluding"
VERSION_END_EXCLUDING = "versionEndExcluding"
VERSION_END_INCLUDING = "versionEndIncluding"

ANY_SYMBOL = "*"
ALL_SYMBOL = "-"
MODIFIED = "modified"



def parse_timestamp(ts):
    return dt.strptime(ts, LAST_MODIFIED_DATE_FORMAT)

def get_last_modified_date(metadata):
    """Gets the last modified date from the metadata string.
    
    Args:
        metadata -- meta file string
    Returns:
        str -- timestamp
    """
    re_match = re.match(r'lastModifiedDate:(.*)\r\n', metadata)
    if re_match and len(re_match.groups()) > 0:
        return parse_timestamp(re_match.groups()[0])
    else:
        print("Error reading last modified date.")

def get_json_as_dict(feed_name):
    request = requests.get(CVE_ZIP_URL_TEMPLATE % str(feed_name))
    zip_file = zipfile.ZipFile(BytesIO(request.content))
    return json.load(zip_file.open(CVE_JSON_FILE_TEMPLATE % str(feed_name)))

def get_pg_connection():
    db_config = json.load(open(DB_CONFIG_FILE))
    user = db_config["user"]
    password = db_config["password"]
    database = db_config["database"]
    return psycopg2.connect(dbname=database, user=user, password=password)



class CVE:
    
    def __set_id(self, id_string):
        """Takes the id string, parses out year and number, and sets it.
        
        Args:
            id_string -- string version of cve id CVE-X-Y
        """
        self.id = int("".join(CVE_ID_RE.match(id_string).groups()))
    
    def __set_scores(self, impact):
        self.v2_score = impact['baseMetricV2']['cvssV2']['baseScore'] if 'baseMetricV2' in impact else None
        self.v3_score = impact['baseMetricV3']['cvssV3']['baseScore'] if 'baseMetricV3' in impact else None
        
    
    def __init__(self, item_json):
        self.__set_id(item_json['cve']['CVE_data_meta']['ID'])
        self.__set_scores(item_json['impact'])
        self.description = item_json['cve']['description']['description_data'][0]["value"]
        self.published_date = item_json['publishedDate']
        self.last_modified_date = item_json["lastModifiedDate"]
        
    def values(self):
        """Gets the values for insertion into PostgreSQL Table.
        """
        return (self.id, self.description, self.v2_score, self.v3_score,
                self.published_date, self.last_modified_date)



def cpe_factory(cve_id, match):
    """Returns either a CPE or a CPERange object.
    
    Args:
        cve -- CVE that this CPE corresponds to.
        match -- json object that contains URI and range properties.
    Returns:
        CPEEntity or CPERange -- Depending on the JSON will return the appropriate entity.
    """
    class CPEEntity:
        """
        For CPEs with a single version.
        """
        def __init__(self, cve_id, product, version):
            self.cve_id = cve_id
            self.product = product
            self.version = version

        def values(self):
            """Provides values for insertion into cpes table.
            """
            # Schema follows (cve_id, product, version, published_date, last_modified_date)
            return (self.cve_id, self.product, self.version)
        
        def is_range(self):
            return False
        
    class CPERange:
        """
        For CPEs with a range.
        """
        def __set_version(self, range_dict):
            self.version_start = range_dict.get(VERSION_START_EXCLUDING, None) or range_dict.get(VERSION_START_INCLUDING, None)
            self.version_end = range_dict.get(VERSION_END_EXCLUDING, None) or range_dict.get(VERSION_END_INCLUDING, None)
            self.start_inclusive = None
            self.end_inclusive = None
            if (VERSION_START_EXCLUDING in range_dict) or (VERSION_START_INCLUDING in range_dict):
                self.start_inclusive = not range_dict.get(VERSION_START_EXCLUDING, False)
            if (VERSION_END_EXCLUDING in range_dict) or (VERSION_END_INCLUDING in range_dict):
                self.end_inclusive = not range_dict.get(VERSION_END_EXCLUDING, False)
        
        def __init__(self, cve_id, product, range_dict):
            self.cve_id = cve_id
            self.product = product
            self.version = ANY_SYMBOL
            self.__set_version(range_dict)

        
        def values(self):
            """Provides values for insertion into cpes table.
            """
            # Schema follows (cve_id, product, version_start, version_end, start_inclusive, end_inclusive)
            return (self.cve_id,
                    self.product,
                    self.version_start,
                    self.version_end, 
                    self.start_inclusive,
                    self.end_inclusive
                   )
        
        def is_range(self):
            return True
        
    uri = match["cpe23Uri"]
    try:
        cpe = CPE2_3_FS(uri)
    except ValueError:
        print("Bad URI: %s" % uri)
        return

    version = cpe.get_version()[0]
    product = cpe.get_product()[0]
    if version == ANY_SYMBOL:
        return CPERange(cve_id, product, match)
    elif version != ALL_SYMBOL:
        return CPEEntity(cve_id, product, version)



def get_cpes(cve_id, nodes):
    """Recurses through the nodes and extracts CPEEntities or CPERanges.
    
    Args:
        cve_id -- The cve_id that corresponds to these matches.
        nodes -- A part of the matching statement that contains CPEs.
    Returns:
        list<CPEEntity/CPERange> -- Returns a list of CPEEntities and CPERanges
    """
    cpes = []
    for node in nodes:
        if "children" in node:
            cpes.extend(get_cpes(cve_id, node["children"]))
        elif 'cpe_match' in node:
            for match in node['cpe_match']:
                if match["vulnerable"]:
                    cpe = cpe_factory(cve_id, match)
                    if cpe:
                        cpes.append(cpe)
    return cpes



def parse_entities(json_dict):
    """Parse the cve, cpe, and cpe_range entities from the json feed.
    
    Args:
        json_dict -- Dict version of JSON file read for a single year.
    Returns:
        list<CVE> -- The new CVEs listed in the data.
        list<CPEEntity> -- The CPEs that correspond to the CVEs.
        list<CPERange> -- The CPERanges that correspond to the CVEs.
    """
    cves = []
    # Make CPEs and CPERanges sets to avoid duplicates over editions.
    cpes = set()
    cpe_ranges = set()
    for item in json_dict["CVE_Items"]:
        cve = CVE(item)
        cves.append(cve.values())
        for cpe in get_cpes(cve.id, item["configurations"]["nodes"]):
            if cpe.is_range():
                cpe_ranges.add(cpe.values())
            else:
                cpes.add(cpe.values())
    return cves, cpes, cpe_ranges



def save_entities(cur, conn, cves, cpes, cpe_ranges):
    """Saves all of the entities that have been read from the json file.
    
    Args:
        cves -- Objects of type CVE to be saved
        cpes -- Objects of type CPE to be saved
        cpe_ranges -- Objects of type CPE_Range to be saved.
    """
    
    # Save CVEs
    args_str = b','.join(cur.mogrify("(%s,%s,%s,%s,%s,%s)", cve) for cve in cves)
    cur.execute(b"INSERT INTO cves VALUES " + args_str)
    conn.commit()

    # Save CPEs
    args_str = b','.join(cur.mogrify("(%s,%s,%s)", cpe) for cpe in cpes)
    cur.execute(b"INSERT INTO cpes VALUES " + args_str)
    conn.commit()

    # Save CPE_Ranges
    args_str = b','.join(cur.mogrify("(%s,%s,%s,%s,%s,%s)", cpe_range) for cpe_range in cpe_ranges)
    cur.execute(b"INSERT INTO cpe_ranges VALUES " + args_str + b" ON CONFLICT DO NOTHING")
    conn.commit()
    
def remove_entities_by_cve_id(cur, conn, cve_ids):
    """Deletes any entities associated with the given cve_ids.

    Args:
        cur -- Cursor
        conn -- Connection
    """
    # Delete CVEs
    sql = 'DELETE FROM cves where id IN %s'
    cur.execute(sql, (tuple(cve_ids),))
    conn.commit()

    # Delete CPEs
    sql = 'DELETE FROM cpes where cve_id IN %s'
    cur.execute(sql, (tuple(cve_ids),))
    conn.commit()

    # Delete CPE_Ranges
    sql = 'DELETE FROM cpe_ranges where cve_id IN %s'
    cur.execute(sql, (tuple(cve_ids),))
    conn.commit()


def main():
    conn = get_pg_connection()
    cur = conn.cursor()
    response = requests.get(MODIFIED_METAFILE_PATH)
    newest_modified_date = ""
    
    # Get the most recent modified meta data
    if response.status_code == 200:
        newest_modified_date = get_last_modified_date(response.text)
    else:
        print("Error loading metafile: %s" % MODIFIED_METAFILE_PATH)
        return
    
    if path.exists(LAST_UPDATE_FILE):
        last_update_datetime = parse_timestamp(open(LAST_UPDATE_FILE, "r").read())
        # Then we need to check if the table needs an update
        if newest_modified_date - last_update_datetime > timedelta(minutes=UPDATE_INTERVAL):
            print("Need to update data.")
            json_dict = get_json_as_dict(MODIFIED)
            cves, cpes, cpe_ranges = parse_entities(json_dict)

            remove_entities_by_cve_id(cur, conn, [cve[0] for cve in cves])
            save_entities(cur, conn, cves, cpes, cpe_ranges)

            print("Replaced modified entities.")
        else:
            print("Data up to date.")
            return
    else: # This means we are going to need to reupload all data
        # Drop existing tables and recreate
        cur.execute(open("sql/create_tables.sql", "r").read())
        conn.commit()
        print("Created Tables")
        
        for year in YEAR_RANGE:
            json_dict = get_json_as_dict(str(year))
            print("Read %s." % (CVE_JSON_FILE_TEMPLATE % year))
            time_start = time.time()
            cves, cpes, cpe_ranges = parse_entities(json_dict)
            save_entities(cur, conn, cves, cpes, cpe_ranges)
            print("Took %d seconds to save entities from %s.\n" % (round(time.time() - time_start), CVE_JSON_FILE_TEMPLATE % year))
    open(LAST_UPDATE_FILE, "w").write(newest_modified_date.strftime(LAST_MODIFIED_DATE_FORMAT))
    cur.close()
    conn.close()

if __name__ == "__main__":
    main()

