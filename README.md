# Vul_data_Knowledge_Graph

## Project introduction

We display the constructed vulnerability knowledge graph in Neo4j 4.4.5. We use cypher language to query vulnerability information, display vulnerability data in a visual way, and give the analysis diagram after the vulnerability node is embedded.

## Requirements

- Windows10
- Python 3.9.0
- neo4j 4.4.5

## Install

`pip install pyspider`

`pip install neo4j`

## Run

cd Connected

python neo4j_vul.py

## Result

![image-20230324023406955](https://github.com/liqiqiqiqi/demo/blob/master/image-20230324023356556.png)

`match(m:vul_data{name:"capec109"})-[r]-(n:vul_data) return m,n`

![image-20230324023242850](https://github.com/liqiqiqiqi/demo/blob/master/image-20230324023242850.png)
