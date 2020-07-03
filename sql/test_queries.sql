#### Query 1: What are the top 10 most vulnerable products? (Based on the number of CVEs associated with them on a version basis.) ####


# Total considering CVE_Ranges and CPES
# Gets Product, Version, CVE_ID for CPE_Ranges then appends to 
# Product, Version, CVE_ID from CPEs
# Then groups over Product, Version and Counts distinct CVE_IDs
select product, version, count(distinct cve_id) as cve_count from (
    select distinct_cpes.product, distinct_cpes.version, cpe_ranges.cve_id
    from cpe_ranges
    join (select distinct product, version from cpes) distinct_cpes on cpe_ranges.product = distinct_cpes.product
    where (CASE WHEN version_start is not NULL then (CASE WHEN start_inclusive then version >= version_start else  version >= version_start END)
                ELSE true END) 
            and 
            (CASE WHEN version_end is not NULL then (CASE WHEN end_inclusive then version <= version_end else  version < version_end END)
                ELSE true END)

    UNION 

    SELECT product, version, cve_id
    from cpes
    ) t
group by product, version
ORDER BY cve_count DESC
LIMIT 10;

#### Query 2: Show the breakdown of the number of CVEs per whole-number score (round up) ####

# For V2
select ceil(v2_score), count(id)
from cves
group by ceil(v2_score);

# For V3
select ceil(v3_score), count(id)
from cves
group by ceil(v3_score);





