-- Create a keyspace
CREATE KEYSPACE IF NOT EXISTS tenant_space WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : '1' };
