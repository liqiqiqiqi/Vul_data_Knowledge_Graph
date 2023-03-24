import csv
import py2neo
from py2neo import Graph,Node,Relationship,NodeMatcher

g=Graph('http://localhost:7474',user='neo4j',password='admin')
print('successed')
#删除原有数据库中的结点，重新生成数据库
#！！！谨慎执行   删除所有结点
# g.run('match (n) detach delete n')

with open('final_data.csv','r',encoding='utf-8') as f:   #使用csv文件进行知识图谱创建
    reader = csv.reader(f)
    for item in reader:
        if reader.line_num==1:   #第一行是head  tail  relation 省略不写
            continue
        print("当前行数：",reader.line_num,"当前内容：",item)
        start_node = Node("vul_data",name=item[0])
        end_node = Node("vul_data",name=item[1])
        relation = Relationship(start_node,item[2],end_node)
        start_node["description"] = item[3]
        g.merge(start_node,"vul_data","name")
        g.merge(end_node,"vul_data","name")
        g.merge(relation,"vul_data","name")

print("over!!!")