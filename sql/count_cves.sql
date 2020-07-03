# Counting form CVEs
SELECT product, version, count(*) as cve_count
from cpes
group by product, version;


# Counting just from CVE Ranges
select product, version, count(distinct cve_id) as cve_count from (
    select cpes.product, cpes.version, cpe_ranges.cve_id
    from cpe_ranges
    join cpes on cpe_ranges.product = cpes.product
    where (CASE WHEN version_start is not NULL then (CASE WHEN start_inclusive then version >= version_start else  version >= version_start END)
                ELSE true END) 
            and 
            (CASE WHEN version_end is not NULL then (CASE WHEN end_inclusive then version <= version_end else  version < version_end END)
                ELSE true END)
    ) t
group by product, version;


# Total considering CVE_Ranges and CPES
select product, version, count(distinct cve_id) as cve_count from (
    # From CPE_Ranges
    select cpes.product, cpes.version, cpe_ranges.cve_id
    from cpe_ranges
    join cpes on cpe_ranges.product = cpes.product
    where (CASE WHEN version_start is not NULL then (CASE WHEN start_inclusive then version >= version_start else  version >= version_start END)
                ELSE true END) 
            and 
            (CASE WHEN version_end is not NULL then (CASE WHEN end_inclusive then version <= version_end else  version < version_end END)
                ELSE true END)
    UNION 
    # From CPEs
    SELECT product, version, cve_id
    from cpes
    ) t
group by product, version;
