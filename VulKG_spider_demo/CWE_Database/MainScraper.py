from urllib.request import urlopen as uReq
from bs4 import BeautifulSoup as soup
import bisect
from neo4j import GraphDatabase
import cwetools as ctools

def cvesearch(CVE_name):

    # Sometimes the CVE_name has a comma at the end,
    # which will break the program.

    if CVE_name[-1] == ",":
        CVE_name = CVE_name[0:-1]
    
    description = ""
    severity = ""
    target_row = ""

    try:
        
        my_url = ("https://nvd.nist.gov/vuln/detail/" + CVE_name)
        
        uClient = uReq(my_url)
        page_html = uClient.read()
        uClient.close()
        ps = soup(page_html, "html.parser")

    except Exception as e:
        print(e,e.args)
    
    try:
        # Target is the main column with all of the CVE info
        target = ps.body.div.findNextSibling().div.findNextSibling().div.findNextSibling().table.tr.td.div.div
        description = target.find("p",{"data-testid":"vuln-description"}).text.replace('\\', r'\\\\').replace('"', r'\"')

        grade = None

        # Each CVE has a "panel" that contains a possible CVSS score
        # for both CVSS Version 3 and 2. This uses the CVSS v.3 score
        # unless it doesn't have one, then it will use the CVSS v.2 score.
        grade_target = target.find("div",{"id":"vulnCvssPanel"})
        
        version3 = grade_target.find("div",{"id":"Vuln3CvssPanel"})
        version3grade = version3.div.div.findNextSibling().span.span.a.text
        if str(version3grade) == "N/A":
            version2 = grade_target.find("div",{"id":"Vuln2CvssPanel"})
            version2grade = version2.div.div.findNextSibling().span.span.a.text
            severity = version2grade
            
        else:
            severity = version3grade
            
        severities = severity.split(" ")
        severity = severities[1]
        severity_number = float(severities[0])

        CVEInput2 = CVE_name[0:3] + CVE_name[4:8] + CVE_name[9:]

        query = "({}:CVE {{type: "'"attack-pattern"'",id: "'"{}-{}"'",name: "'"{}"'",description: "'"{}"'",severity: "'"{}"'",severity_number: {}}})".format(CVEInput2,CVE_name[4:8],CVE_name[9:],CVE_name,description,severity,severity_number)

        return query
            
    except:
        print("No CVE found by the name of " + CVE_name)


#-----------------------------------------------------------------*
# scrapeCWE will scrape a CWE web page given its URL.
#-----------------------------------------------------------------*
#                           Parameters
#-----------------------------------------------------------------+
# CWE_id_number: ID of CWE that the method will scrape.
# --------------
# usnode: the list of already-created nodes. This list will ensure
# that when the program is made for several CWEs, that it won't
# create duplicate nodes.
# --------------
# cwe_cwe_bool: a boolean variable that determines whether the CWE
# will create relationships or not. If it is a CWE that was a branch
# of a relationship of an original node, it will not create any.
#---------------
# original_info: contains the original CWE ID that the "branch" CWE 
# came from and also contains a string that is the relationship 
# between the original CWE and the "branch" CWE.
#------------------------------------------------------------------+

#------------------------------------------------------------------+
# scrapeCWE at the current moment will web scrape the following info:
# -------------------------------
# - CWE Name and ID
# - Applicable Platforms of CWE
#   > Languages
#   > Operating Systems
#   > Architectures
#   > Paradigms
#   > Technologies
# - Observed Examples of CVEs
#   > CVE ID
# - Detection Methods
#   > Method name
#   > Effectiveness
# - Likelihood of Exploit
# - CWE to CWE relationships
#------------------------------------------------------------------+

def scrapeCWE(CWE_id_number, usnode, cwe_cwe_bool, original_info):
    
    cwe_name = " "

    try:

        # Choose url of CWE to be scraped

        my_url = ("https://cwe.mitre.org/data/definitions/{0}.html".format(CWE_id_number))
        print("==========")
        uClient = uReq(my_url)
        page_html = uClient.read()
        uClient.close()
        print(my_url,page_html)
        ps = soup(page_html, "html.parser")

        # Web page is ready to scrape

        cwe_name = ps.h2.contents[0] # Gets the title of the CWE

        print(cwe_name)
        print("")

    except:

        # For when you want to loop through every CWE
        
        if CWE_id_number < 1350:
            scrapeCWE(CWE_id_number+1,usnode,cwe_cwe_bool,original_info)
        elif CWE_id_number == 1351:
            scrapeCWE(2000,usnode,cwe_cwe_bool,original_info)
        
    #---------------------------------------------------->
    # Finding the Applicable Platforms of the CWE
    #---------------------------------------------------->

    # This code block finds the correct category, and then
    # proceeds to go to the correct div tag to work inside of.

    try:
        container = ps.find("div",{"id":"Applicable_Platforms"})

        first_div = container.div
        target_div = first_div.findNextSibling()

        first_div = target_div.div.div              
        language_div = first_div                       

        temp = language_div

    except:
        None

    #------------------------------------------

    # Creates empty lists for all of the possible platforms
    # that the CWE could be in, so that they are ready to be
    # filled, if the scraper finds the corresponding category.

    languages = []
    operating_systems = []
    architectures = []
    paradigms = []
    technologies = []

    #---------------Language-------------------

    try:
        if language_div.p.contents[0] == "Languages":
            temp = temp.findNext().findNext()

            for i in range(len(language_div) - 2):
                lang = temp.p.contents[0].strip()
                frequency = temp.p.span.contents[0].strip()
                languages.append([lang,frequency])
                try:
                    if (temp.findNextSibling().contents[0] == "Technologies"):
                        temp = temp.findNextSibling()
                        break
                except:
                    None
                temp = temp.findNextSibling()
    except:
        None

    #------------Operating Systems-------------    

    try:
        if temp.contents[0] == "Operating Systems" or language_div.p.contents[0] == "Operating Systems":
            temp = temp.findNextSibling()
            os = temp.p.contents[0].strip()
            frequency = temp.p.span.contents[0].strip()
            operating_systems.append([os,frequency])
            while (temp.findNextSibling() != None):
                temp = temp.findNextSibling()
                os = temp.p.contents[0].strip()
                frequency = temp.p.span.contents[0].strip()
                operating_systems.append([os,frequency])
    except:
        None

    #--------------Architectures---------------    

    try:
        if temp.contents[0] == "Architectures" or language_div.p.contents[0] == "Architectures":
            temp = temp.findNextSibling()
            arch = temp.p.contents[0].strip()
            frequency = temp.p.span.contents[0].strip()
            architectures.append([arch,frequency])
            while (temp.findNextSibling() != None):
                temp = temp.findNextSibling()
                arch = temp.p.contents[0].strip()
                frequency = temp.p.span.contents[0].strip()
                operating_systems.append([arch,frequency])
    except:
        None

    #----------------Paradigms-----------------    

    try:
        if temp.contents[0] == "Paradigms" or language_div.p.contents[0] == "Paradigms":
            temp = temp.findNextSibling()
            para = temp.p.contents[0].strip()
            frequency = temp.p.span.contents[0].strip()
            paradigms.append([para,frequency])
            while (temp.findNextSibling() != None):
                temp = temp.findNextSibling()
                para = temp.p.contents[0].strip()
                frequency = temp.p.span.contents[0].strip()
                operating_systems.append([para,frequency])
    except:
        None   

    #--------------Technologies----------------    
        
    try:        
        if temp.contents[0] == "Technologies" or language_div.p.contents[0] == "Technologies":
            temp = temp.findNextSibling()
            tech = temp.p.contents[0].strip()
            frequency = temp.p.span.contents[0].strip()
            technologies.append([tech,frequency])
            while (temp.findNextSibling() != None):
                temp = temp.findNextSibling()
                tech = temp.p.contents[0].strip()
                frequency = temp.p.span.contents[0].strip()
                technologies.append([tech,frequency])
    except:
        None

    #---------End of Applicable Platform Finders---------X

    #---------------------------------------------------->
    # Finding the Common Consequences
    #---------------------------------------------------->

    common_consequences = []

    try:
        container = ps.find("div",{"id":"Common_Consequences"})

        first_div = container.div
        target_div = first_div.findNextSibling()

        tbody_div = target_div.div.div.table

        temp = tbody_div.tr.findNextSibling()   # First common consequence row

        while temp != None:
            impacts = temp.i.contents[0].split("; ")
            impacts[0] = impacts[0].strip()
            scope = temp.td.contents[0::2]
            com_cons = ""
            for word in scope:
                com_cons += word + " "

            com_cons = com_cons[0:-1]
                
            common_consequences.append([com_cons,impacts])
            temp = temp.findNextSibling()
        

    except:
        None


    #----------------------------------------------------X

    #---------------------------------------------------->
    # Finding the Observed Examples of CVEs
    #---------------------------------------------------->

    cve_list = []

    try: 

        container = ps.find("div",{"id":"Observed_Examples"})

        first_div = container.div

        target_div = first_div.findNextSibling()

        cve_table = target_div.div.div.table

        cve_item = cve_table.tr

        for i in range(int(len(cve_table) / 2) - 1):
            cve_item = cve_item.findNextSibling()
            cve_id = cve_item.a.contents[0][4:]
            if cve_id[-1] == ",":
                cve_id = cve_id[0:-1]
            cve_list.append(cve_id)

    except:
        None
        
    #---------------End of Observed CVEs-----------------X

    #---------------------------------------------------->
    # Finding the Related Attack Patterns (CAPECs)
    #---------------------------------------------------->

    capec_list = []

    try: 

        container = ps.find("div",{"id":"Related_Attack_Patterns"})

        first_div = container.div

        target_div = first_div.findNextSibling()

        capec_table = target_div.div.div.table

        capec = capec_table.tr

        for i in range(int(len(capec_table)-1/2)):
            capec = capec.findNextSibling()
            capec_name_div = capec.td
            capec_name = capec_name_div.a.contents[0]
            capec_desc = capec_name_div.findNextSibling().contents[0]
            capec_list.append([capec_name,capec_desc])
                  
    except:
        None
        
    #---------------End of Finding CAPECs-----------------X

    #---------------------------------------------------->
    # Finding the Detection Methods
    #---------------------------------------------------->

    detection_methods = []

    try:
        container = ps.find("div",{"id":"Detection_Methods"})

        first_div = container.div
        target_div = first_div.findNextSibling()

        det_methods_table = target_div.div.div.table

        det_item = det_methods_table.tr    

        while (det_item != None):   
            method = det_item.td.p.contents[0].strip()
            try:
                effectiveness = (det_item.findAll("p"))[-1].contents[0]
                detection_methods.append([method,effectiveness])
            except:
                detection_methods.append(method)
            det_item = det_item.findNextSibling()
            
    except:
        None

    #--------------End of Detection Methods--------------X

    #---------------------------------------------------->
    # Finding the Likelihood of Exploit
    #---------------------------------------------------->

    exploit_likelihood = []

    try:
        container = ps.find("div",{"id":"Likelihood_Of_Exploit"})
        target_div = container.div.findNextSibling().div.div
        exploit_likelihood = target_div.contents[0]
            
    except:
        None

    #------------End of Likelihood of Exploit------------X


    #---------------------------------------------------->
    # Finding the CWE Relationships
    #---------------------------------------------------->

    relationships = []
    id_numbers = []
    names = []
    paired_relationships = []

    if cwe_cwe_bool is True:
        try:

            # Adds the relationships for the first table
            
            container = ps.find("div",{"id":"Relationships"})
            
            # Takes a lot of digging to get to correct tag...
            first_div = container.div.findNextSibling() 
            table_div = first_div.div.div.div # references the specific table
            even_further_div = table_div.div.div.div.div.div.table
            target_div = even_further_div.tbody 

            rel_cwe = target_div.tr

            while (rel_cwe != None):
                relationships.append(rel_cwe.td.contents[0])
                id_numbers.append(int(rel_cwe.td.findNextSibling().findNextSibling().contents[0]))
                names.append(rel_cwe.td.findNextSibling().findNextSibling().findNextSibling().a.contents[0])
                rel_cwe = rel_cwe.findNextSibling()

            # Checks if there is more than one relationship table,
            # adds the relationships for the other tables if applicable
            #----------------------------------------------------

            table_div = table_div.findNextSibling()

            while (table_div != None):
                even_further_div = table_div.div.div.div.div.div.table # table tag
                target_div = even_further_div.tbody

                rel_cwe = target_div.tr
                

                while (rel_cwe != None):
                    id_number = int(rel_cwe.td.findNextSibling().findNextSibling().contents[0])
                    name = rel_cwe.td.findNextSibling().findNextSibling().findNextSibling().a.contents[0]
                    if id_number not in id_numbers:
                        relationships.append(rel_cwe.td.contents[0])
                        id_numbers.append(id_number)
                        names.append(name)
                    rel_cwe = rel_cwe.findNextSibling()

                table_div = table_div.findNextSibling()


            for i in range(len(relationships)):
                paired_relationships.append([relationships[i],id_numbers[i]])
                          
        except Exception as e:
            None
            # print(e,e.args) #In case you need to see the exception

    #-----------------End of Relationships---------------X

##  Important Variables in scrapeCWE
##CWE_id_number
##cwe_name
##languages        #
##operating_systems# These 5 variables can merge 
##architectures    # into 'applicable_platforms' 
##paradigms        # variable
##technologies     #
##cve_list
##detection_methods
##exploit_likelihood
##paired_relationships
##capec_list
##common_consequences


    #---------------------------------------------------------------------->
    #
    #                             Neo4j CWE Import
    #
    #---------------------------------------------------------------------->

    count = 1
    neo4j_create_nodes = "create "
    neo4j_match_statement = ""
    neo4j_create_rels = "create "

    if binsearch(usnode[2],CWE_id_number) is False:
        bisect.insort(usnode[2],CWE_id_number)
        create_cwe_node = "create (z:CWE {{name: "'"CWE-{1}"'",description:"'"{0}"'",id_number:{1}".format(cwe_name,CWE_id_number)
        create_cwe_node += ",exploit_likelihood:"'"{}"'"}})".format(exploit_likelihood)
        execute_commands(create_cwe_node)


    #--------------Applicable Platform Relationship Code-----------------
    
    neo4j_match_statement += "match (a:CWE) where a.id_number = {} ".format(CWE_id_number)

    for language in languages:
        if language[0] not in usnode[0][0]:
            usnode[0][0].append(language[0])
            neo4j_create_nodes += ",(a{}:Language {{name: "'"{}"'"}})".format(count,language[0])
            count += 1
            
        neo4j_match_statement += "match (a{0}:Language) where a{0}.name = "'"{1}"'" ".format(count,language[0])
        neo4j_create_rels += ",(a)-[:FOUNDIN {{prevalence:"'"{}"'"}}]->(a{})".format(language[1],count)
        count += 1
        
    for os in operating_systems:
        if os[0] not in usnode[0][1]:
            usnode[0][1].append(os[0])
            neo4j_create_nodes  += ", (a{}:OS {{name: "'"{}"'"}})".format(count,os[0])
            count += 1
            
        neo4j_match_statement += "match (a{0}:OS) where a{0}.name = "'"{1}"'" ".format(count,os[0])
        neo4j_create_rels += ",(a)-[:FOUNDIN {{prevalence:"'"{}"'"}}]->(a{})".format(os[1],count)
        count += 1

    for arch in architectures:
        if arch[0] not in usnode[0][2]:
            usnode[0][2].append(arch[0])
            neo4j_create_nodes += ",(a{}:Architecture {{name: "'"{}"'"}})".format(count,arch[0])
            count += 1
            
        neo4j_match_statement += "match (a{0}:Architecture) where a{0}.name = "'"{1}"'" ".format(count,arch[0])
        neo4j_create_rels += ",(a)-[:FOUNDIN {{prevalence:"'"{}"'"}}]->(a{})".format(arch[1],count)
        count += 1

    for paradigm in paradigms:
        if paradigm[0] not in usnode[0][3]:
            usnode[0][3].append(paradigm[0])
            neo4j_create_nodes += ",(a{}:Paradigm {{name: "'"{}"'"}})".format(count,paradigm[0])
            count += 1
            
        neo4j_match_statement += "match (a{0}:Paradigm) where a{0}.name = "'"{1}"'" ".format(count,paradigm[0])
        neo4j_create_rels += ",(a)-[:FOUNDIN {{prevalence:"'"{}"'"}}]->(a{})".format(paradigm[1],count)
        count += 1

    for tech in technologies:
        if tech[0] not in usnode[0][4]:
            usnode[0][4].append(tech[0])
            neo4j_create_nodes += ",(a{}:Technology {{name: "'"{}"'"}})".format(count,tech[0])
            count += 1

        neo4j_match_statement += "match (a{0}:Technology) where a{0}.name = "'"{1}"'" ".format(count,tech[0])
        neo4j_create_rels += ",(a)-[:FOUNDIN {{prevalence:"'"{}"'"}}]->(a{})".format(tech[1],count)
        count += 1

    #-------------------------------------------------------------------X

    #-----------------------CVEs Relationship Code-----------------------
        
    for cve in cve_list:
        if not binsearch(usnode[5],cve):    # CVE id's are strings by default, but can still 
            bisect.insort(usnode[5],cve)    # be magically be found via binary search
            statement = str(cvesearch("CVE-"+cve))
            if statement != "None":
                neo4j_create_nodes += "," + statement

        
        neo4j_match_statement += "match (a{0}:CVE) where a{0}.id = "'"{1}-{2}"'" ".format(count,cve[0:4],cve[5:])
        neo4j_create_rels += ",(a)-[:VULNERABLETO]->(a{})".format(count)
        count += 1
        

    #-------------------------------------------------------------------X
        
    #-----------------------CAPECs Relationship Code---------------------
        
    for capec in capec_list:
            
        if binsearch(usnode[3],int(capec[0][6:])) is False:
            bisect.insort(usnode[3],int(capec[0][6:]))
            neo4j_create_nodes += ",(a{2}:CAPEC {{id_number: {0}, description: "'"CAPEC-{0}: {1}"'"}})".format(int(capec[0][6:]),capec[1],count)
            count += 1

        neo4j_match_statement += "match (a{0}:CAPEC) where a{0}.id_number = {1} ".format(count,int(capec[0][6:]))
        neo4j_create_rels += ",(a)<-[:ATTACKPATTERNFOR]-(a{})".format(count)
        count += 1

    #-------------------------------------------------------------------X

        # A better way to connect tools is to do them separately in
        # the cwetools.py file after you have run this program.

##    #-----------------------Tools Relationship Code----------------------
##        
##    if "Class: Language-Independent" in ([i[0] for i in languages]):
##        for tool in ctools.all_tools:
##            for product in tool[1:]:
##                if binsearch(product[1:],CWE_id_number):
##                    neo4j_match_statement += "match (a{0}:Tool) where a{0}.name = "'"{1}"'" ".format(count,product[0])
##                    neo4j_match_statement += "and a{}.language = "'"{}"'" ".format(count,tool[0])
##                    neo4j_create_rels += ", (a)<-[:FINDS]-(a{})".format(count)
##                    count += 1
##    else:
##        for tool in ctools.all_tools:
##            if tool[0] in ([i[0] for i in languages]):  
##                for product in tool[1:]:
##                    if binsearch(product[1:],CWE_id_number):
##                        neo4j_match_statement += "match (a{0}:Tool) where a{0}.name = "'"{1}"'" ".format(count,product[0])
##                        neo4j_match_statement += "and a{}.language = "'"{}"'" ".format(count,tool[0])
##                        neo4j_create_rels += ", (a)<-[:FINDS]-(a{})".format(count)
##                        count += 1
##
##    #-------------------------------------------------------------------X

    #----------------Common Consequences Relationship Code---------------


    for consequence in common_consequences: 

        if consequence[0] not in ([item[0] for item in usnode[4][3:]]):
            usnode[4].append([consequence[0],[]])
            neo4j_create_nodes += ",(a{}:Consequence {{name: "'"{}"'"}})".format(count,consequence[0])
            usnode[4][0][consequence[0]] = usnode[4][1]
            usnode[4][1] += 1
            count += 1

        cons_match_count = count
        neo4j_match_statement += "match (a{0}:Consequence) where a{0}.name = "'"{1}"'" ".format(count,consequence[0])
        neo4j_create_rels += ", (a)-[:VIOLATES]->(a{})".format(count)
        count += 1
        

        for impact in consequence[1]:
            if impact not in usnode[4][2]:
                usnode[4][2].append(impact)
                neo4j_create_nodes += ",(a{}:Impact {{name: "'"{}"'"}})".format(count,impact)
                count += 1

            if impact not in usnode[4][usnode[4][0][consequence[0]]][1]:
                usnode[4][usnode[4][0][consequence[0]]][1].append(impact)
                
                neo4j_match_statement += "match (a{0}:Impact) where a{0}.name = "'"{1}"'" ".format(count,impact)
                neo4j_create_rels += ", (a{})-[:CAUSES]->(a{})".format(cons_match_count,count)
                count += 1
            
    

    #-------------------------------------------------------------------X

    #----------------Detection Methods Relationship Code-----------------
        
    for detmet in detection_methods:

        if detmet[0] not in usnode[1]:
            usnode[1].append(detmet[0])
            neo4j_create_nodes += ",(a{}:Detection_Method {{name: "'"{}"'"}})".format(count,detmet[0])
            count += 1

        neo4j_match_statement += "match (a{0}:Detection_Method) where a{0}.name = "'"{1}"'" ".format(count,detmet[0])

        # If this block of code causes an error, it means the detection method did not have
        # a listed effectiveness and will cause an error since it will not be a parsable string.
        # So, the effectiveness will just be listed as N/A for that detection method for the CWE.
        try:
            if detmet[1][0] != " ":
                effectiveness = " ".join(detmet[1].split(" ")[1:])     
                neo4j_create_rels += ",(a)<-[:DETECTS {{effectiveness:"'"{}"'"}}]-(a{})".format(effectiveness,count)
            else:
                neo4j_create_rels += ",(a)<-[:DETECTS {{effectiveness:"'"N/A"'"}}]-(a{})".format(count)
            count += 1
        except:
            neo4j_create_rels += ",(a)<-[:DETECTS {{effectiveness:"'"N/A"'"}}]-(a{})".format(count)
            count += 1

    #-------------------------------------------------------------------X

            

    #--------------------Importing all Data (except CWEs) into Neo4j------------------*
    if len(neo4j_create_nodes) != 7 and len(neo4j_create_rels) != 7:
        neo4j_create_nodes = neo4j_create_nodes[:7] + neo4j_create_nodes[8:]
        neo4j_create_rels = neo4j_create_rels[:7] + neo4j_create_rels[8:]
        
        execute_commands(neo4j_create_nodes)
        final_statement = neo4j_match_statement + neo4j_create_rels
        execute_commands(final_statement)

    elif len(neo4j_create_nodes) == 7 and len(neo4j_create_rels) != 7:
        neo4j_create_rels = neo4j_create_rels[:7] + neo4j_create_rels[8:]

        final_statement = neo4j_match_statement + neo4j_create_rels
        execute_commands(final_statement)

    #---------------------------------------------------------------------------------X

        
    
    #------------------CWE - to - CWE Relationship Code------------------


    if cwe_cwe_bool is True:
    
        cwe_cwe_sentence = "match (a:CWE) where a.id_number = {} ".format(CWE_id_number)
        create_section = "create "

        for relation in paired_relationships:
            
            # For relationship CWEs that haven't been made yet.
            if not binsearch(usnode[2],relation[1]):
                usnode = scrapeCWE(relation[1],usnode,False,[CWE_id_number,relation[0]])
                
            # For relationship CWEs that HAVE been made already.
            else:
                
                cwe_cwe_sentence += "match (a{0}:CWE) where a{0}.id_number = {1} ".format(count,relation[1])
                create_section += ",(a)-[:{0}]->(a{1})".format(relation[0].upper(),count)
                count += 1
                
        # If there are no relationships for a CWE, the length of create_section
        # ("create ") will be 7 and no clauses will be inputted into Neo4j.
        if len(create_section) != 7:
            create_section = create_section[:7] + create_section[8:]
            final_statement = cwe_cwe_sentence + create_section
            execute_commands(final_statement)
        
    else:

        cwe_cwe_sentence = "match (a:CWE) where a.id_number = {} ".format(original_info[0])
        cwe_cwe_sentence += "match (b:CWE) where b.id_number = {} ".format(CWE_id_number)
        final_statement = cwe_cwe_sentence + "create (a)-[:{}]->(b)".format(original_info[1].upper())
        execute_commands(final_statement)
        
            
        
        
            

        #-------------------------------------------------------------------X
         

    return usnode

#-----------------------------------End of ScrapeCWE Code--------------------------------------------------X


# addCWEType will add the CWE type to CWE nodes by setting 
# another label to them (Example: add 'Base' label to CWE-79).

def addCWETypes(usnode):

    # Going to CWE-2000 (CWE Dictionary) to scrape types for all CWEs

    my_url = ("https://cwe.mitre.org/data/definitions/2000.html")

    uClient = uReq(my_url)
    page_html = uClient.read()
    uClient.close()

    ps = soup(page_html, "html.parser")

    # CWE-2000 page is ready to scrape

    membership_section = ps.find("div",{"id":"Membership"})
    membership_table = membership_section.div.findNextSibling().div.div.div
    membership_table = membership_table.table.tbody

    match_statement = ""
    set_labels = ""
    type_count = 1
    execution_counter = 0
    
    for row in membership_table:
        type_ = row.td.findNextSibling()
        type_name = type_.span.span.text.split(" ",maxsplit = 1)[0]
        id_num = int(type_.findNextSibling().text)
        if binsearch(usnode[2],id_num):
            match_statement += "match (a{0}:CWE) where a{0}.id_number = {1} ".format(type_count,id_num)
            set_labels += "set a{}:{} ".format(type_count,type_name)
            type_count += 1
            execution_counter += 1

            # Makes this part much more efficient by executing
            # in large blocks rather than individual clauses.
            if execution_counter % 100 == 0 or id_num == max(usnode[2]):
                final_statement = match_statement + set_labels
                execute_commands(final_statement)
                print("Executed : ", execution_counter)
                match_statement = ""
                set_labels = ""

        

#--------------------------------------End of Web Scraper Code---------------------------------------------------X


#-------------------Binary Search----------------------->

def binsearch(list_to_check, target_number):
    left = 0
    right = len(list_to_check) - 1
    moves = 0
    while (left <= right):
        mid = int((left + right) / 2)
        moves += 1
        if (list_to_check[mid] == target_number):
            return True 
        elif (list_to_check[mid] < target_number):
            left = mid + 1
        else:
            right = mid - 1
    
    return False

#-------------------------------------------------------X
    
#---------------Neo4j Method Used in Import------------->
        
# uri = "host link"
# auth = ("neo4j", password) of database being used

# Turn boolean to True or False depending on if you want to
# import data to Neo4j. Making it False allows you just see
# web scrape info, and makes the program much faster.

def execute_commands(transaction_execution_commands,boolean = True):
    if boolean is True:
        data_base_connection = GraphDatabase.driver(uri = "bolt://localhost:7687", auth=("neo4j", "admin"))
        session = data_base_connection.session()
        session.run(transaction_execution_commands)

#-------------------------------------------------------X


#-------------------------Main Functions-------------------------->

def forMain(node_list):
    cwe_to_add = []
    answer = None

    usnode = node_list
        
    while True:
        answer = int(input("Enter CWE ID to put into database. Enter -1 to stop adding CWEs. "))
        if answer == -1:
            break
        cwe_to_add.append(answer)
    for cwe in cwe_to_add:
        print("----------------------------------------------")
        usnode = scrapeCWE(cwe,usnode,True,None)

    addCWETypes(usnode)

#----------------------------------------------------

def whileMain(node_list):
    id_num = None
    
    usnode = node_list

    while id_num != -1:
        print("----------------------------------------------")
        id_num = int(input("Enter ID of the CWE to scrape or -1 to end: "))
        if (id_num == -1):
            break
        usnode = scrapeCWE(id_num,usnode,True,None)

    addCWETypes(usnode)

#----------------------------------------------------

def addNeoInfo(node_list):
    
    num_of_cwe = int(input("CWEs go until ID number 1350. How many CWEs would you like to add? "))
    last_check = input("Are you sure? Exit if not.")

    usnode = node_list

    for i in range(1, num_of_cwe + 1):
        usnode = scrapeCWE(i,usnode,True,None)
        
    addCWETypes(usnode)

#--------------------------------------------------------X        
         
#------------------------------Main-------------------------------#

def main():

    consequence_dict = {}
    consequence_index = 3
    
    used_nodes_list = [[[],[],[],[],[]],[],[],[],[consequence_dict,consequence_index,[]],[]]
##    Indices:                 0         1  2  3                    4                     5
##    ------------------------------------------------------    
##    used_nodes_list[0] is the 5 Applicable Platforms
##    [0][0] - Languages , [0][1] OS , [0][2] Architectures
##    [0][3] - Paradigms , [0][4] Technologies
##    ------------------------------------------------------
##    used_nodes_list[1] is the Detection Methods
##    used_nodes_list[2] is the CWE IDs
##    used_nodes_list[3] is the CAPECs
##    used_nodes_list[4] is the Common Consequences
##    used_nodes_list[5] is the CVE IDs
    
    print("The for-loop or while-loop main?")
    print("Enter 1 for for-loop, 2 for while-loop, or 3 for Neo4j import.")
    answer = int(input("Enter number: "))
    if answer == 1:
        forMain(used_nodes_list)
    elif answer == 2:
        whileMain(used_nodes_list)
    elif answer == 3:
        addNeoInfo(used_nodes_list)

    # It's faster to delete duplicate relations at the end, than to check each time.
    delete_duplicate_rels = "match (s)-[r]->(e)with s,e,type(r) as typ, tail(collect(r)) as coll foreach(x in coll | delete x)"
    execute_commands(delete_duplicate_rels)
    

main()
