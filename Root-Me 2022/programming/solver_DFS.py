from pwn import *
import re


def dfs(graph, start, visited=None):
    if visited is None:
        visited = set()
    visited.add(start)
    for next in (graph[start] - visited):
        dfs(graph, next, visited)
    return visited

pattern = re.compile(r"\d+")
host,port = "ctf10k.root-me.org", 8001
r = remote(host,port)
nodes = dict()
data = r.recvuntil(b"> ").decode().split("\n")
print(data)
tmp = [int(i) for i in pattern.findall(data[1])]
path_from ,path_to = tmp[3],tmp[2]
data = data[2:-1]
for i in data: 
    nums = pattern.findall(i)
    nums = [int(i) for i in nums]
    node,n = nums[0],nums[1:]
    nodes[node] = set(n)

visited = list(dfs(nodes,path_from))
if path_to in visited:
    r.sendline(b"yes")
    print("i sent yes")
else:    
    r.sendline(b"no")
    print("i sent no")
for i in range(59):
    nodes = dict()

    data = r.recvuntil(b"> ").decode().split("\n")
    #print(data)
    tmp = [int(i) for i in pattern.findall(data[1])]
    path_from ,path_to = tmp[3],tmp[2]
    data = data[2:-1]
    for i in data: 
        nums = pattern.findall(i)
        nums = [int(i) for i in nums]
        node,n = nums[0],nums[1:]
        nodes[node] = set(n)

    visited = list(dfs(nodes,path_from))
    if path_to in visited:
        r.sendline(b"yes")
        print("i sent yes")
    else:    
        r.sendline(b"no")
        print("i sent no")


print(r.recvuntil(b"\n"))

print(r.recvuntil(b"\n"))
