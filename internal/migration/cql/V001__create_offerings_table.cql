-- Create a table
CREATE TABLE IF NOT EXISTS ocm.offerings (
partition text,
region text,
country text,
tenantId text,
groupId text,
requestId text,
last_update_timestamp timestamp,
type text,
metadata text,
offerParams text,
status text,
PRIMARY KEY ((partition,region,country,tenantId),groupid,requestId)
) WITH default_time_to_live = 17800;
