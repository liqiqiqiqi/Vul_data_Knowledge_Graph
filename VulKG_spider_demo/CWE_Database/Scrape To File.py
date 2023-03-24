def main():
    comma = False
    found_object = False
    file2 = open("bundle.json", 'w')
    print("{\n\t\"type\": \"bundle\",\n\t\"id\": \"bundle--c9b519fc-1b72-4d15-b3b9-0a5f10f0c205\",\n\t\"objects\": [")
    file2.write("{\n\t\"type\": \"bundle\",\n\t\"id\": \"bundle--c9b519fc-1b72-4d15-b3b9-0a5f10f0c205\",\n\t\"objects\": [")
    with open ("records.json") as file1:
        for line in file1:

            if ("}" in line) & (found_object == True):
                print("\t\t}", end='')
                file2.write("\t\t}")
                found_object = False
            if found_object == True:
                print("\t\t\t" + line, end='')
                file2.write("\t\t\t" + line)
            if "\"properties\": {" in line:
                if comma:
                    print(",")
                    file2.write(",")
                print("\t\t{")
                file2.write("\n\t\t{\n")
                comma = True
                found_object = True
    file1.close()

    inside1 = False
    inside2 = False
    relationship = False
    first = False
    after_relation = False
    i = 0

    with open("relrecords.json") as file3:
        for line in file3:

            if "\"segments\": [" in line:
                inside2 = True
                first = True
                print(",\n\t\t{")
                file2.write(",\n\t\t{")

            if ("[" in line) and inside2:
                inside1 = True

            if ("],"  in line) and not inside1:
                inside2 = False
            elif ("],"  in line) & inside1:
                inside1 = False

            if inside2:
                if "\"id\":" in line and first:
                    print("\t\t\t\"source_ref\": " + line[6:], end='')
                    file2.write("\n\t\t\t\"source_ref\": " + line[6:])
                    first = False
                elif "\"id\":" in line and after_relation:
                    print("\t\t\t\"target_ref\": " + line[6:], end='')
                    file2.write("\t\t\t\"target_ref\": " + line[6:])
                    print("\t\t\t\"type\": \"relationship\",")
                    file2.write("\t\t\t\"type\": \"relationship\",")
                    print("\t\t\t\"id\": \"relationship" + str(i) + "\"")
                    file2.write("\n\t\t\t\"id\": \"relationship" + str(i) + "\"")
                    i += 1
                    print("\t\t}", end='')
                    file2.write("\n\t\t}")
                    after_relation = False

            if "\"relationship\": {" in line:
                relationship = True
            if relationship:
                if "\"type\": " in line:
                    print("\t\t\t\"relationship_type\": "  + line[8:], end='')
                    file2.write("\t\t\t\"relationship_type\": "  + line[8:])
                    after_relation = True
            if "}," in line:
                relationship = False

    print("\n\t]\n}")
    file2.write("\n\t]\n}")

    file3.close()
    file2.close()

main()
