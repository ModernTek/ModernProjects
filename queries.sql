/*Exploitable and SUSPICIOUS */
 select  PROJECT,  VERSION,  EXPLOIT_COUNT, SUSPICIOUS_COUNT
from ( 
      select 
                       sum( case when lookupindex=4 then 1 else 0 end ) as EXPLOIT_COUNT,
				sum(case when lookupindex=3 then 1 else 0 end) as SUSPICIOUS_COUNT,
				p.name as PROJECT, pv.name as VERSION
from 	fortify.defaultissueview i
inner join fortify.projectversion pv on pv.id = i.projectversion_id
inner join fortify.artifact a on a.projectversion_id =i.projectversion_id	
inner join fortify.project p on p.id = pv.project_id
join fortify.auditvalueview av on av.issue_id =i.id
where pv.active='Y'
and a.status = 'PROCESS_COMPLETE'
and 	i.hidden='N'
and 	i.suppressed = 'N' and i.scanstatus <> 'REMOVED'
and a.srcartifact_id = (select max(srcartifact_id) from fortify.artifact
                        where projectversion_ID = a.projectversion_id
                        and active='Y'
                        and status='PROCESS_COMPLETE')
AND uploadDate >= TO_DATE('01-01-2016', 'MM-DD-yyyy') 
AND uploadDate <  TO_DATE('01-31-2016', 'MM-DD-yyyy') 
                  + INTERVAL '1' DAY
group by p.name, pv.name)

/* fundings */
 select
  p.name as project, pv.name as version, count(i.id) as findings
from 	fortify.defaultissueview i
inner join fortify.projectversion pv on pv.id = i.projectversion_id
inner join fortify.artifact a on a.projectversion_id =i.projectversion_id	
inner join fortify.project p on p.id = pv.project_id
where pv.active='Y'
and a.status = 'PROCESS_COMPLETE'
--added on 5/9/2016
and a.id in (select max(id) from fortify.artifact where projectversion_id = i.projectversion_id)
--added on 5/9/2016-
and 	i.hidden='N'
and 	i.suppressed = 'N' and i.scanstatus <> 'REMOVED'
--Deleted 2/6/2016--------------------------------------
--Added again 8/1/2016---------------
and 	(i.friority='Critical' OR i.friority='High')
--Added again 8/1/2016---------------------
--Deleted 2/6/2016----------------------------------------
AND uploadDate >= TO_DATE('01-01-2016', 'MM-DD-yyyy') 
AND uploadDate <  TO_DATE('01-31-2016', 'MM-DD-yyyy') 
                  + INTERVAL '1' DAY
group by p.name, pv.name


/* Removed suspicious and exploitable.*/
 select  PROJECT,  VERSION,  EXPLOIT_COUNT_REMOVED, SUSPICIOUS_COUNT_REMOVED
from ( 
      select 
                       sum( case when lookupindex=4 then 1 else 0 end ) as EXPLOIT_COUNT_REMOVED,
				sum(case when lookupindex=3 then 1 else 0 end) as SUSPICIOUS_COUNT_REMOVED,
				p.name as PROJECT, pv.name as VERSION
from 	fortify.defaultissueview i
inner join fortify.projectversion pv on pv.id = i.projectversion_id
inner join fortify.artifact a on a.projectversion_id =i.projectversion_id	
inner join fortify.project p on p.id = pv.project_id
join fortify.auditvalueview av on av.issue_id =i.id
where pv.active='Y'
and a.status = 'PROCESS_COMPLETE'
and  (i.scanstatus = 'REMOVED' or i.hidden='Y' or i.suppressed = 'Y')
AND uploadDate >= TO_DATE('08-03-2015', 'MM-DD-yyyy') 
AND uploadDate <  TO_DATE('10-14-2015', 'MM-DD-yyyy') 
                  + INTERVAL '1' DAY                
group by p.name, pv.name)
where (SUSPICIOUS_COUNT_REMOVED != 0 or EXPLOIT_COUNT_REMOVED !=0)




Splunk Combined:

 select  PROJECT,  VERSION,  EXPLOIT_COUNT, SUSPICIOUS_COUNT
from ( 
      select 
                       sum( case when lookupindex=4 then 1 else 0 end ) as EXPLOIT_COUNT,
				sum(case when lookupindex=3 then 1 else 0 end) as SUSPICIOUS_COUNT,
				p.name as PROJECT, pv.name as VERSION
from 	fortify.defaultissueview i
inner join fortify.projectversion pv on pv.id = i.projectversion_id
inner join fortify.artifact a on a.projectversion_id =i.projectversion_id	
inner join fortify.project p on p.id = pv.project_id
join fortify.auditvalueview av on av.issue_id =i.id
where pv.active='Y'
and a.status = 'PROCESS_COMPLETE'
and 	i.hidden='N'
and 	i.suppressed = 'N' and i.scanstatus <> 'REMOVED'
AND uploadDate >= TO_DATE('08-03-2015', 'MM-DD-yyyy') 
AND uploadDate <  TO_DATE('08-11-2015', 'MM-DD-yyyy') 
                  + INTERVAL '1' DAY
group by p.name, pv.name)" | join type=left [|dbquery Fortify2 "select  PROJECT,  VERSION,  EXPLOIT_COUNT_REMOVED, SUSPICIOUS_COUNT_REMOVED
from ( 
      select 
                       sum( case when lookupindex=4 then 1 else 0 end ) as EXPLOIT_COUNT_REMOVED,
				sum(case when lookupindex=3 then 1 else 0 end) as SUSPICIOUS_COUNT_REMOVED,
				p.name as PROJECT, pv.name as VERSION
from 	fortify.defaultissueview i
inner join fortify.projectversion pv on pv.id = i.projectversion_id
inner join fortify.artifact a on a.projectversion_id =i.projectversion_id	
inner join fortify.project p on p.id = pv.project_id
join fortify.auditvalueview av on av.issue_id =i.id
where pv.active='Y'
and a.status = 'PROCESS_COMPLETE'
and  (i.scanstatus = 'REMOVED' or i.hidden='Y' or i.suppressed = 'Y')
AND uploadDate >= TO_DATE('08-03-2015', 'MM-DD-yyyy') 
AND uploadDate <  TO_DATE('08-11-2015', 'MM-DD-yyyy') 
                  + INTERVAL '1' DAY                
group by p.name, pv.name)
where (SUSPICIOUS_COUNT_REMOVED != 0 or EXPLOIT_COUNT_REMOVED !=0)
