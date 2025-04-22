-- Create a keyspace
CREATE KEYSPACE IF NOT EXISTS tenant_space WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : '1' };

-- Create a table
CREATE TABLE IF NOT EXISTS tenant_space.offerings (
partition text,
region text,
country text,
groupId text,
requestId text,
last_update_timestamp timestamp,
type text,
metadata text,
offerParams text,
status text,
PRIMARY KEY ((partition,region,country),groupid,requestId)
) WITH default_time_to_live = 17800;