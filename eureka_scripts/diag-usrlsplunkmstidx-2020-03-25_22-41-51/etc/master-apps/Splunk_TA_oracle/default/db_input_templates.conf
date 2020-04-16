# This file provides template inputs for use with DB Connect 3.1.X and above.
# Note: If you are using DB Connect 2.x, please consult to dbx2.inputs.conf.template


[oracle:database]
description = Collect Oracle database information
interval = 7200
index_time_mode = current
mode = batch
query = SELECT * FROM V$DATABASE
sourcetype = oracle:database

[oracle:instance]
description = Collect Oracle instance information
interval = 7200
index_time_mode = current
mode = batch
query = SELECT * FROM v$instance \
CROSS JOIN (SELECT VALUE as NLS_CHARACTERSET FROM nls_database_parameters WHERE parameter='NLS_CHARACTERSET') \
CROSS JOIN (SELECT VALUE as NLS_LANGUAGE FROM nls_database_parameters WHERE parameter='NLS_LANGUAGE')  \
CROSS JOIN (SELECT VALUE as NLS_TERRITORY FROM nls_database_parameters WHERE parameter='NLS_TERRITORY') \
CROSS JOIN (SELECT VALUE as NLS_SORT FROM nls_database_parameters WHERE parameter='NLS_SORT')
sourcetype = oracle:instance

[oracle:session]
description = Collect Oracle session information
interval = 900
index_time_mode = current
mode = batch
query = SELECT * FROM V$SESSION CROSS JOIN \
(SELECT instance_name, host_name FROM v$instance)
sourcetype = oracle:session

[oracle:tablespace]
description = Collect Oracle tablespace information
interval = 3600
index_time_mode = current
mode = batch
query = SELECT * FROM DBA_TABLESPACES
sourcetype = oracle:tablespace

[oracle:tablespaceMetrics]
description = Collect Oracle tablespace metrics
interval = 900
index_time_mode = current
mode = batch
query = SELECT TABLESPACE_NAME, TOTAL_BYTES, TOTAL_BLOCKS, FREE_BYTES, USED_BYTES \
FROM (\
  SELECT D.TABLESPACE_NAME, TOTAL_BYTES, TOTAL_BLOCKS,FREE_BYTES, TOTAL_BYTES - NVL(FREE_BYTES, 0) "USED_BYTES" \
  FROM (\
    SELECT TABLESPACE_NAME, SUM (BYTES) TOTAL_BYTES, SUM (BLOCKS) TOTAL_BLOCKS \
    FROM DBA_DATA_FILES GROUP BY TABLESPACE_NAME) D, (\
      SELECT TABLESPACE_NAME, SUM (BYTES) FREE_BYTES \
      FROM DBA_FREE_SPACE GROUP BY TABLESPACE_NAME) F \
      WHERE D.TABLESPACE_NAME = F.TABLESPACE_NAME(+) \
      UNION ALL \
      SELECT D.TABLESPACE_NAME, TOTAL_BYTES, TOTAL_BLOCKS,NVL(FREE_BYTES, 0) "FREE_BYTES", USED_BYTES \
      FROM (\
        SELECT TABLESPACE_NAME, SUM(BYTES) TOTAL_BYTES, SUM(BLOCKS) TOTAL_BLOCKS \
        FROM DBA_TEMP_FILES GROUP BY TABLESPACE_NAME) D, (\
          SELECT TABLESPACE_NAME, SUM(BYTES_USED) USED_BYTES, SUM(BYTES_FREE) FREE_BYTES \
          FROM V$TEMP_SPACE_HEADER GROUP BY TABLESPACE_NAME) F \
          WHERE D.TABLESPACE_NAME = F.TABLESPACE_NAME(+))
sourcetype = oracle:tablespaceMetrics

[oracle:sga]
description = Collect Oracle System Global Area (SGA) information
interval = 300
index_time_mode = current
mode = batch
query = SELECT NAME, TOTAL, FREE \
FROM ( \
  SELECT 'SGA' NAME,  (SELECT SUM(VALUE) FROM V$SGA) TOTAL,  (\
      SELECT SUM(BYTES) FROM V$SGASTAT \
      WHERE NAME = 'free memory') FREE  FROM DUAL  ) \
      UNION \
      SELECT NAME, TOTAL, TOTAL - USED FREE \
      FROM ( SELECT 'PGA' NAME,  (\
        SELECT VALUE FROM V$PGASTAT \
        WHERE NAME = 'aggregate PGA target parameter') TOTAL, \
        (SELECT VALUE FROM V$PGASTAT WHERE NAME = 'total PGA allocated') USED  FROM DUAL  ) \
        UNION \
        SELECT NAME, TOTAL, FREE  FROM (\
          SELECT 'Shared pool' NAME,  \
          (SELECT SUM(BYTES) FROM V$SGASTAT WHERE POOL = 'shared pool' GROUP BY POOL) TOTAL,  \
          (SELECT BYTES FROM V$SGASTAT WHERE NAME = 'free memory' and POOL = 'shared pool') FREE  FROM DUAL  )  \
          UNION  \
          SELECT NAME, TOTAL, FREE  FROM (\
            SELECT 'Large pool' NAME,  \
            (SELECT SUM(BYTES) FROM V$SGASTAT WHERE POOL = 'large pool' GROUP BY POOL) TOTAL,  \
            (SELECT BYTES FROM V$SGASTAT WHERE POOL = 'large pool' AND NAME = 'free memory') FREE  FROM DUAL  )
sourcetype = oracle:sga

[oracle:libraryCachePerf]
description = Collect Oracle cache metrics
interval = 60
index_time_mode = current
mode = batch
query = SELECT NAMESPACE, GETS, GETHITS, GETHITRATIO, PINS, PINHITS, PINHITRATIO, \
RELOADS, INVALIDATIONS, DLM_LOCK_REQUESTS, DLM_PIN_REQUESTS, DLM_PIN_RELEASES, \
DLM_INVALIDATION_REQUESTS, DLM_INVALIDATIONS \
FROM V$LIBRARYCACHE
sourcetype = oracle:libraryCachePerf

[oracle:dbFileIoPerf]
description = Collect Oracle I/O performance metrics
interval = 120
index_time_mode = current
mode = batch
query = SELECT 'DB_FILE' TYPE, D.NAME FILE_NAME, F.PHYRDS, F.PHYWRTS, F.AVGIOTIM, F.MINIOTIM, F.MAXIOWTM, F.MAXIORTM \
FROM V$FILESTAT F, V$DATAFILE D WHERE F.FILE# = D.FILE#  \
UNION \
SELECT 'TEMP_DB_FILE' TYPE, T.NAME FILE_NAME,  F.PHYRDS, F.PHYWRTS, F.AVGIOTIM, F.MINIOTIM, F.MAXIOWTM, F.MAXIORTM \
FROM V$FILESTAT F, V$TEMPFILE T  WHERE F.FILE# = T.FILE#  ORDER BY 1
sourcetype = oracle:dbFileIoPerf

[oracle:osPerf]
description = Collect Oracle host performance metrics
interval = 300
index_time_mode = current
mode = batch
query = SELECT STAT_NAME, VALUE, CUMULATIVE FROM V$OSSTAT
sourcetype = oracle:osPerf

[oracle:osPerf:10g]
description = Collect Oracle 10g host performance metrics
interval = 300
index_time_mode = current
mode = batch
query = SELECT STAT_NAME, VALUE, 'YES' as CUMULATIVE FROM V$OSSTAT
sourcetype = oracle:osPerf

[oracle:sysPerf]
description = Collect Oracle system performance metrics
interval = 60
index_time_mode = current
mode = rising
query = SELECT * FROM V$SYSMETRIC_HISTORY \
CROSS JOIN (SELECT instance_name, HOST_NAME FROM v$instance) \
WHERE END_TIME > ? \
ORDER BY END_TIME ASC
rising_column_index = 2
sourcetype = oracle:sysPerf

[oracle:connections]
description = Collect Oracle connections performance metrics
interval = 300
index_time_mode = current
mode = batch
query = SELECT instance_name, HOST_NAME, connections FROM v$instance \
CROSS JOIN (SELECT count(*) as connections FROM v$session WHERE username is NOT null)
sourcetype = oracle:connections

[oracle:connections:pool]
description = Collect Oracle connections pool performance metrics
interval = 300
index_time_mode = current
mode = batch
query = SELECT host_name, instance_name, active_pooled_connections, total_pooled_connections \
FROM v$instance \
CROSS JOIN (\
  SELECT count(case when status='active' then 1 end) active_pooled_connections, count(*) total_pooled_connections \
  FROM DBA_CPOOL_INFO)
sourcetype = oracle:pool:connections

[oracle:table]
description = Collect Oracle tables information
interval = 300
index_time_mode = current
mode = batch
query = SELECT host_name, instance_name, all_tables.*, dba_segments.bytes, All_TAB_MODIFICATIONS.timestamp as last_update_time \
FROM all_tables \
LEFT JOIN All_TAB_MODIFICATIONS on all_tables.table_name=All_TAB_MODIFICATIONS.table_name \
LEFT JOIN dba_segments on dba_segments.segment_name=all_tables.table_name  \
CROSS JOIN (SELECT host_name, instance_name FROM v$instance) WHERE dba_segments.segment_type='TABLE'
sourcetype = oracle:table

[oracle:database:size]
description = Collect Oracle database size metrics
interval = 300
index_time_mode = current
mode = batch
query = SELECT HOST_NAME, instance_name,current_size FROM v$instance \
CROSS JOIN (SELECT round((sum(bytes)/1024/1024),2) as current_size FROM v$datafile)
sourcetype = oracle:database:size

[oracle:user]
description = Collect Oracle users metrics
interval = 900
index_time_mode = current
mode = batch
query = SELECT * FROM ALL_USERS CROSS JOIN (SELECT host_name, instance_name FROM v$instance)
sourcetype = oracle:user

[oracle:query]
description = Collect Oracle queries performance metrics
interval = 600
index_time_mode = current
mode = batch
query = SELECT\
   instance_name,   host_name,   all_users.username,   all_users.user_id,\
sql_id, sql_fulltext, plan_hash_value, DECODE(command_type,11,'ALTERINDEX',15,'ALTERTABLE',170,'CALLMETHOD',9,'CREATEINDEX',1,'CREATETABLE',7,'DELETE' ,50,'EXPLAIN',2,'INSERT',26,'LOCKTABLE',47,'PL/SQLEXECUTE',3,'SELECT',6,'UPDATE',189,'UPSERT') command_name,\
    CASE\
        WHEN executions > 0\
        THEN ROUND(elapsed_time/executions,3)\
        ELSE NULL\
    END elap_per_exec,\
    parsing_schema_name,    module,    elapsed_time,\
    executions,\
    PHYSICAL_READ_BYTES/1024 read_kb,\
    buffer_gets,\
    rows_processed\
FROM v$sqlarea,all_users \
CROSS JOIN (SELECT instance_name,host_name FROM v$instance) \
WHERE v$sqlarea.PARSING_USER_ID = all_users.user_id
sourcetype = oracle:query


[oracle:audit:unified]
description = Collect Oracle Audit Unified. It can be used only with Oracle versions 12 and above.
interval = 300
mode = rising
query = SELECT * \
FROM ( \
  SELECT CAST((event_timestamp at TIME zone 'UTC') AS TIMESTAMP) EVENT_TIMESTAMP_UTC,u.* \
  FROM UNIFIED_AUDIT_TRAIL u) \
WHERE EVENT_TIMESTAMP_UTC > ? \
ORDER BY EVENT_TIMESTAMP_UTC ASC
rising_column_index = 1
index_time_mode = dbColumn
input_timestamp_column_index = 1
sourcetype = oracle:audit:unified
