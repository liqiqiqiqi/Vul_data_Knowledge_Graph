from neo4j import GraphDatabase

# All of the tools I've researched and found available CWE standards for... so far
#---------------------------------------------------------------------------------

# absint - astree for C/C++
        # more accurate CWEs
astree_accurate = ["Astree - Accurate",118,119,120,121,122,124,125,126,127,128,129,131,188,190,191,194,195,196,197,362,364,365,366,367,369,398,404,411,415,416,456,457,471,476,478,567,587,588,662,665,667,672,680,681,682,685,686,690,761,764,765,785,786,787,805,806,823,824,832,833,835,908]
        # less accurate CWES
astree_less_accurate = ["Astree - Less Accurate",15,73,77,78,79,88,89,90,91,99,117,123,130,134,170,193,240,242,252,253,328,401,466,467,468,475,477,481,497,558,561,562,573,611,628,643,663,666,676,704,754,759,763,767,783,789,807,822,825,831]

# flawfinder is for C/C++ source code
flawfinder_cplpl = ["Flawfinder",20,22,78,119,120,126,134,190,250,327,362,377,676,732,785,807,829]
flawfinder_c = flawfinder_cplpl

# codesonar
        # for both C and C++
codesonar_accurate_cplpl = ["CodeSonar",14,15,20,22,73,78,88,89,90,99,114,119,120,128,131,134,136,170,190,191,192,197,200,227,242,243,252,256,259,269,275,281,284,311,313,316,318,319,321,325,326,327,328,330,331,332,334,338,362,364,366,367,369,377,390,391,394,398,400,401,410,411,413,415,416,427,452,457,459,465,474,475,476,477,478,484,485,489,506,511,540,546,547,557,558,561,562,563,567,570,571,573,587,589,590,605,610,615,628,641,657,662,664,665,666,667,672,674,675,676,680,681,682,686,687,688,690,691,696,704,710,758,760,761,762,763,764,765,771,772,773,775,780,783,785,786,788,789,798,823,832,835,843,863,870,908,910,1007,1037,1041,1056,1064,1077,1080,1091,1126,1127,1155,1156,1157,1158,1159,1160,1161,1162,1163,1164,1165,1166,1167,1168,1169,1170,1171,1172,1211,1215,1226,1295]
codesonar_accurate_c = codesonar_accurate_cplpl
        # did not include broad CWEs, only the most accurate ones
codesonar_accurate_java = ["CodeSonar",22,74,78,79,89,90,94,95,113,117,187,190,197,200,227,237,252,253,259,287,295,319,326,327,328,330,332,349,390,395,396,397,398,400,412,413,440,456,470,476,477,480,481,485,491,492,501,502,522,524,538,547,561,563,567,570,572,573,581,585,595,596,597,607,609,611,614,628,643,662,664,665,674,682,686,704,710,732,749,768,771,772,820,833,909,913,916]



# kiuwan security application platform
kiuwan_aspnet = ["Kiuwan SAST",11,12,16,20,79,94,113,185,200,259,285,288,295,302,346,388,489,497,522,548,556,613,614,646,693,778,807,863,1022]
kiuwan_cplpl = ["Kiuwan SAST",77,78,88,119,120,129,131,134,135,170,190,193,242,252,273,363,367,379,401,415,416,457,467,476,479,563,590,628,676,681,682,684,696,705,835]
kiuwan_csharp = ["Kiuwan SAST",15,20,22,73,77,78,79,89,90,91,93,94,99,113,114,117,120,185,200,203,209,233,235,252,256,284,285,287,310,311,312,315,320,321,326,327,330,338,345,346,350,352,377,390,395,396,398,404,426,434,449,459,470,476,489,494,497,499,501,502,532,539,544,563,566,567,581,601,606,611,614,643,652,754,760,776,780,784,798,835,862,918,943]
kiuwan_java = ["Kiuwan SAST",5,7,15,16,20,22,73,77,78,79,80,89,90,91,93,95,99,111,113,114,117,129,134,159,180,185,200,209,235,245,246,256,260,265,275,284,285,287,296,297,298,299,310,311,312,315,320,321,325,326,327,328,329,330,338,345,346,350,352,353,358,359,362,374,375,382,383,384,391,395,396,397,404,459,470,476,478,481,484,486,489,491,494,497,499,500,501,502,522,532,539,552,563,564,566,567,568,572,574,575,576,577,578,579,580,581,582,584,585,586,597,601,606,611,613,614,615,617,643,676,693,698,749,760,776,784,798,835,915,918,927,943]
kiuwan_javascript = ["Kiuwan SAST",11,16,20,22,73,77,78,79,80,89,90,93,94,95,99,113,183,185,200,209,235,259,295,311,312,315,319,320,321,326,327,330,338,346,352,358,359,398,472,476,501,502,539,563,601,611,614,615,643,644,646,693,730,776,798,943,1004]
kiuwan_php = ["Kiuwan SAST",15,16,22,73,77,78,79,89,90,91,93,95,98,99,113,116,117,129,134,159,185,200,209,235,256,310,311,312,315,320,321,326,327,330,338,346,352,359,434,473,489,501,502,522,539,563,566,601,606,611,613,614,615,643,676,698,760,776,784,835,862,918,943]
kiuwan_python = ["Kiuwan SAST",20,22,73,77,78,79,80,89,90,91,93,94,99,113,117,134,185,200,209,235,259,260,285,287,310,311,312,315,320,321,326,327,328,329,330,338,345,346,350,352,359,391,426,470,472,501,502,532,539,561,566,601,606,611,613,614,615,639,643,698,760,776,784,798,835,915,918,943,1004]
kiuwan_kotlin = ["Kiuwan SAST",79,111,200,311,326,359,502,539,561,581,614]
kiuwan_scala = ["Kiuwan SAST",15,22,77,78,79,89,90,91,93,94,95,99,111,113,114,117,134,159,185,200,209,235,256,260,285,310,311,312,315,320,321,325,326,327,328,329,330,338,345,346,350,352,359,400,470,494,499,501,502,522,539,566,601,606,611,613,614,643,676,760,776,784,798,835,918,943]
kiuwan_html = ["Kiuwan SAST",20,358,359,434,525,549,830,1022]


# oversecured - Java and Kotlin
oversecured = []
        # oversecured writes their cwes in a random list of vulnerabilities...
        # will take a while to do

# synopsys - coverity (static analysis)
coverity_csharp = ["Coverity SAST",11,12,13,22,73,78,79,89,90,91,94,95,117,190,200,209,259,260,284,285,300,313,314,315,317,319,321,327,328,330,352,366,369,390,398,403,404,470,476,480,502,519,532,543,561,563,569,570,573,595,601,610,611,614,615,643,670,683,759,760,776,778,783,798,827,833,835,863,916,942,1004,1275]
coverity_c = ["Coverity SAST",20,22,78,88,89,99,119,120,125,129,131,134,170,188,190,194,195,197,200,209,243,248,252,253,259,290,291,293,313,314,315,317,319,321,327,328,350,366,367,369,377,394,398,400,401,404,415,416,456,457,459,465,467,475,476,480,481,482,483,484,532,561,562,563,569,570,573,590,597,606,617,628,643,662,665,667,670,672,676,681,683,685,686,687,704,710,758,750,760,762,764,770,772,775,783,798,833,835,843,916]
coverity_java = ["Coverity SAST",4,7,20,22,23,36,73,78,79,81,89,90,91,94,95,99,113,116,117,183,185,190,192,200,209,215,218,227,242,252,253,259,260,261,284,285,290,291,293,295,296,297,299,300,311,313,314,315,317,319,321,327,328,330,336,337,350,352,359,366,369,374,382,384,390,391,396,398,400,403,404,419,425,427,440,470,476,480,481,483,484,489,501,502,530,532,538,543,561,563,567,568,569,570,571,572,573,579,580,583,586,595,597,598,601,609,610,611,613,614,615,625,643,650,662,670,672,674,683,693,759,760,770,776,778,783,798,827,833,835,862,863,916,917,921,926,927,942,1023,1032,1035]
coverity_javascript = ["Coverity SAST",20,22,73,74,78,79,88,89,94,95,99,183,200,201,209,219,260,284,285,288,289,295,300,313,314,315,317,319,327,328,330,345,346,352,398,400,476,480,483,484,489,502,532,548,561,565,569,601,611,613,614,625,628,646,665,668,732,755,760,770,776,778,779,783,798,829,922,942,1004,1022,1187]
coverity_kotlin = ["Coverity SAST",22,78,89,94,99,200,209,215,259,296,297,299,313,314,315,317,319,321,327,328,330,336,337,359,427,502,530,532,538,610,611,643,693,759,760,776,778,798,827,916,921,926,927,1032,1035]
coverity_php = ["Coverity SAST",22,74,78,79,88,89,94,95,209,285,313,314,315,317,319,352,398,470,476,480,483,484,502,532,561,569,601,611,665,670,688,783,798]
coverity_python = ["Coverity SAST",20,22,78,79,88,89,94,95,99,200,209,285,295,304,313,314,315,317,319,327,328,330,346,352,377,398,476,480,489,502,521,532,561,569,601,611,614,625,688,760,778,783,798,916,1004,1275]
coverity_ruby = ["Coverity SAST",0,22,73,78,79,83,89,94,95,113,183,184,209,215,259,263,287,289,307,319,321,352,369,398,400,470,476,480,502,521,561,569,599,601,614,639,642,661,665,688,704,777,783,798,862,915,916,1004]
coverity_scala = ["Coverity SAST",190,398,476,480,483,561,569,665,783]
coverity_typescript = ["Coverity SAST",20,22,73,74,78,79,88,89,94,95,99,183,200,201,219,260,284,285,288,289,295,300,313,314,315,317,319,327,328,330,345,346,352,398,400,476,480,483,484,489,502,532,548,561,565,569,601,611,613,614,625,628,646,665,668,670,688,732,755,760,770,776,778,779,783,798,829,922,942,1004,1022,1187]
coverity_go = ["Coverity SAST",22,78,79,88,89,94,99,209,252,259,295,313,314,315,317,319,321,327,328,345,366,369,398,476,480,502,522,532,561,563,569,601,611,617,643,662,667,764,776,778,783,798,833,835]

#----------- Language Tool List --------------

c_tools = ["C",flawfinder_c,coverity_c,astree_accurate,astree_less_accurate,codesonar_accurate_c]
aspnet_tools = ["ASP.NET",kiuwan_aspnet]
cplpl_tools = ["C++",flawfinder_cplpl,kiuwan_cplpl,astree_accurate,astree_less_accurate,codesonar_accurate_cplpl]
csharp_tools = ["C#",kiuwan_csharp,coverity_csharp]
java_tools = ["Java",kiuwan_java,coverity_java,codesonar_accurate_java]
javascript_tools = ["Javascript",kiuwan_javascript,coverity_javascript]
php_tools = ["PHP",kiuwan_php,coverity_php]
python_tools = ["Python",kiuwan_python,coverity_python]
kotlin_tools = ["Kotlin",kiuwan_kotlin,coverity_kotlin]
scala_tools = ["Scala",kiuwan_scala,coverity_scala]
html_tools = ["HTML",kiuwan_html]
ruby_tools = ["Ruby",coverity_ruby]
typescript_tools = ["Typescript",coverity_typescript]
go_tools = ["Go",coverity_go]

all_tools = [c_tools,aspnet_tools,cplpl_tools,csharp_tools,java_tools,javascript_tools,php_tools,python_tools,kotlin_tools,scala_tools,html_tools,ruby_tools,typescript_tools,go_tools]

#-------- Neo4j Creation Nodes --------------------

    # Could easily replace the contents of this function with
    # a loop to make it much more concise, but decided to manually
    # type it since there are not many tools I've found yet.

def create_tools():
    n4j = "create "
    n4j += "(tool1:Tool {name:"'"Astree - Accurate"'",language:"'"C"'"}), "
    n4j += "(tool2:Tool {name:"'"Astree - Less Accurate"'",language:"'"C"'"}), "
    n4j += "(tool3:Tool {name:"'"Astree - Accurate"'",language:"'"C++"'"}), "
    n4j += "(tool4:Tool {name:"'"Astree - Less Accurate"'",language:"'"C++"'"}), "
    n4j += "(tool5:Tool {name:"'"Flawfinder"'",language:"'"C"'"}), "
    n4j += "(tool6:Tool {name:"'"Flawfinder"'",language:"'"C++"'"}), "
    n4j += "(tool7:Tool {name:"'"CodeSonar"'",language:"'"C"'"}), "
    n4j += "(tool8:Tool {name:"'"CodeSonar"'",language:"'"C++"'"}), "
    n4j += "(tool9:Tool {name:"'"CodeSonar"'",language:"'"Java"'"}), "
    n4j += "(tool10:Tool {name:"'"Kiuwan SAST"'",language:"'"ASP.NET"'"}), "
    n4j += "(tool11:Tool {name:"'"Kiuwan SAST"'",language:"'"C++"'"}), "
    n4j += "(tool12:Tool {name:"'"Kiuwan SAST"'",language:"'"C#"'"}), "
    n4j += "(tool13:Tool {name:"'"Kiuwan SAST"'",language:"'"Java"'"}), "
    n4j += "(tool14:Tool {name:"'"Kiuwan SAST"'",language:"'"Javascript"'"}), "
    n4j += "(tool15:Tool {name:"'"Kiuwan SAST"'",language:"'"PHP"'"}), "
    n4j += "(tool16:Tool {name:"'"Kiuwan SAST"'",language:"'"Python"'"}), "
    n4j += "(tool17:Tool {name:"'"Kiuwan SAST"'",language:"'"Kotlin"'"}), "
    n4j += "(tool18:Tool {name:"'"Kiuwan SAST"'",language:"'"Scala"'"}), "
    n4j += "(tool19:Tool {name:"'"Kiuwan SAST"'",language:"'"HTML"'"}), "
    n4j += "(tool20:Tool {name:"'"Coverity SAST"'",language:"'"C#"'"}), "
    n4j += "(tool21:Tool {name:"'"Coverity SAST"'",language:"'"C"'"}), "
    n4j += "(tool22:Tool {name:"'"Coverity SAST"'",language:"'"Java"'"}), "
    n4j += "(tool23:Tool {name:"'"Coverity SAST"'",language:"'"Javascript"'"}), "
    n4j += "(tool24:Tool {name:"'"Coverity SAST"'",language:"'"Kotlin"'"}), "
    n4j += "(tool25:Tool {name:"'"Coverity SAST"'",language:"'"PHP"'"}), "
    n4j += "(tool26:Tool {name:"'"Coverity SAST"'",language:"'"Python"'"}), "
    n4j += "(tool27:Tool {name:"'"Coverity SAST"'",language:"'"Ruby"'"}), "
    n4j += "(tool28:Tool {name:"'"Coverity SAST"'",language:"'"Scala"'"}), "
    n4j += "(tool29:Tool {name:"'"Coverity SAST"'",language:"'"Typescript"'"}), "
    n4j += "(tool30:Tool {name:"'"Coverity SAST"'",language:"'"Go"'"})"
    return n4j

#-------------------------------------------------------------------------------------------

#---------------Neo4j Method Used in Import------------->
        
# uri = "host link"
# auth = ("neo4j", password) of database being used

# Turn boolean to True or False depending on if you want to
# import data to Neo4j. Making it False allows you just see
# web scrape info, and makes the program much faster.

def execute_commands(transaction_execution_commands,boolean = True):
    if boolean is True:
        data_base_connection = GraphDatabase.driver(uri = "bolt://localhost:7687", auth=("neo4j", "54321"))
        session = data_base_connection.session()
        session.run(transaction_execution_commands)

#-------------------------------------------------------X

#--------------Manually add in tools to the Neo4j database---------------

def add_tool_rels():
    for tool in all_tools:
        for specific_tool in tool[1:]:
            create_statement = "create (a:Tool {{name:"'"{}"'", language:"'"{}"'"}}) ".format(specific_tool[0],tool[0])
            match_statement = ""
            count = 0
            for cwe_id in specific_tool[1:]:
                match_statement += "match (a{0}:CWE) where a{0}.id_number = {1} ".format(count,cwe_id)
                create_statement += ",(a)-[:FINDS]->(a{})".format(count)
                count += 1
            final_statement = match_statement + create_statement
            execute_commands(final_statement)

#-----------------------------------------------------------------------X

def main():
    add_tool_rels()

#main()
                
            

    
    





















