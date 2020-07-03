
DROP TABLE IF EXISTS cves;
DROP TABLE IF EXISTS cpes;
DROP TABLE IF EXISTS cpe_ranges;


CREATE TABLE cves (
    id bigint PRIMARY KEY,
    description text,
    v2_score NUMERIC(3, 1),
    v3_score NUMERIC(3, 1),
    published_date timestamp,
    last_modified_date timestamp
);

CREATE UNIQUE INDEX cves_index
on cves (id);

CREATE TABLE cpes (
    -- id serial PRIMARY KEY,
    cve_id bigint NOT NULL,
    product varchar(100) NOT NULL,
    version varchar(100) NOT NULL
);

CREATE UNIQUE INDEX cpes_idx
on cpes (cve_id, product, version);

-- CREATE TABLE cve_matches (
--     cve_id integer NOT NULL,
--     cpe_id integer NOT NULL
-- )


-- CREATE UNIQUE INDEX cve_matches_idx
-- on cpes (cve_id, cpe_id);

CREATE TABLE cpe_ranges (
    cve_id bigint,
    product varchar(100),
    version_start varchar(100),
    version_end varchar(100),
    start_inclusive boolean,
    end_inclusive boolean,
    UNIQUE(cve_id, product, version_start, version_end)
);

CREATE INDEX cpe_ranges_idx
on cpe_ranges (cve_id, product);

