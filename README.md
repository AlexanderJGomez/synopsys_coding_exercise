# synopsys_coding_exercise

**DDL File**: `sql/create_tables.sql`

In order to run the code, you must first indicate the `database`, `user`, and `password` in db_config.json.  

Then, you can run the following command:

```bash
python3 process_json.py
```

If you are running it for the first time, it will insert all of the data from the feed into the database. After that, you will only update using the modified JSON file from the feed if you have not updated in over a minute.

# Query 1
- What are the top 10 most vulnerable products? (Based on the number of CVEs associated with them on a version basis.)

```sql
select product, version, count(distinct cve_id) as cve_count from (
    select distinct_cpes.product, distinct_cpes.version, cpe_ranges.cve_id
    from cpe_ranges
    join (select distinct product, version from cpes) distinct_cpes on cpe_ranges.product = distinct_cpes.product
    where (CASE WHEN version_start is not NULL then (CASE WHEN start_inclusive then version >= version_start ELSE  version >= version_start END)
                ELSE true END) 
            and 
            (CASE WHEN version_end is not NULL then (CASE WHEN end_inclusive then version <= version_end ELSE  version < version_end END)
                ELSE true END)

    UNION 

    SELECT product, version, cve_id
    from cpes
    ) t
group by product, version
ORDER BY cve_count DESC
LIMIT 10;
```

# Query 2
- Show the breakdown of the number of CVEs per whole-number score (round up)

```sql
# For V2
select ceil(v2_score), count(id)
from cves
group by ceil(v2_score);

# For V3
select ceil(v3_score), count(id)
from cves
group by ceil(v3_score);

```


# Future Upgrades:
1. Handling for editions as well
2. Handle case where we haven't updated in >= 8 days
3. Create `products` table to reduce memory usage in `cpes` and `cpe_ranges`
