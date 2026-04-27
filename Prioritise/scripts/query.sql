ORDER BY (
    CASE 
        WHEN (SUBSTR((
            SELECT name 
            FROM sqlite_master WHERE type='table' LIMIT 0,1),1,1)='a') THEN title 
        ELSE date END
    )