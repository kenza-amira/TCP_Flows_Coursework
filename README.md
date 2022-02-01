## Part 1: Identifying elephant TCP flows (10%)

Suppose you are a network engineer working for an Internet Service Provider
(ISP), and  need to identify elephant TCP flows, i.e., those flows that transfer a large amount
of data, in a packet trace captured at a vantage point in the ISP network. Considering this scenario, your task for this assignment is to analyze the packet trace, which is
[202201031400p.pcap.gz](./202201031400p.pcap.gz) (a subset of the [MAWI traffic
trace](http://mawi.wide.ad.jp/mawi/)), and create a Python dictionary
 whose keys are a four-tuple (`<src_ip><dst_ip><src_port><dst_port>`
that identifies a TCP flow and values are total bytes transferred in the flow
(excluding Ethernet, IPv4 or IPv6, and TCP header).  In the four tuple,
IP addresses (32 bits for IPv4 and 128 bits for IPv6) and ports (16 bits) are represented in integer format.  See the Hints section below for what this dictionary looks like in more details.  Ignore packets whose
Protocol field in the IPv4 header or Next Header field in the IPv6 header does
not indicate TCP.  Also, ignore packets in which Scapy does not recognize the TCP header.  Do this task by completing the `__init()__` method of the
`Flow` class in [pcap_flow.py](./pcap_flow.py). Do not remove any existing lines.
When the `__init()__` method is implemented, you can analyze the data and plot the results by:
```
python3 ./pcap_flow.py 202201031400p.pcap.gz
```
This will generate 202201031400p.pcap.gz.flow.pdf, which is the histogram of top 100 flows (in terms of the number of bytes transferred) generated by `Plot` method, and 202201031400p.pcap.gz.flow.data, which includes the dictionary created in the `__init__()` method in the text format.
You can use the small subset of the dataset ([sample.pcap.gz](./sample.pcap.gz)) in the development phase to speed up the cycle. The correct code will produce [sample.pcap.gz.flow.correct.pdf](./sample.pcap.gz.flow.correct.pdf).

### Marking Criteria

1. Your code can count the number of TCP connections in [202201031400p.pcap.gz](./202201031400p.pcap.gz) correctly, which needs to pass the following test
(**4%**):
```
python3 -m pytest tests/test_pcap_flow.py::test_pcap_flow1
```
2. Top 5 flows identified by your code are correct, although the exact byte count can be incorrect, which need to pass the following test (**4%**).
```
python3 -m pytest tests/test_pcap_flow.py::test_pcap_flow2
```
3. Transferred bytes are correctly counted for every TCP connection, which needs to pass the following test (**2%**):
```
python3 -m pytest tests/test_pcap_flow.py::test_pcap_flow3
```
Note that since meeting the second or third criteria needs to meet all the preceding criteria, the possible score is 0%, 4%, 8% or 10%.
Passing those tests is indicative but does not guarantee the corresponding marks.  We may validate the submitted code using
other packet traces.  Cheating like hard-coding the output will lead to 0% mark.

### Hints

The example below, which represent two IPv4 and one IPv6 flows, shows what the dictionary looks like:
```
{(3397673457, 881710188, 40854, 443): 93, (47852906957879642018321573790788953724, 42543033614977941460700748907930394238,
61524, 443): 48, (2748517542, 2106321627, 22, 53878): 1080}
```
IP addresses (first two elements in the tuples) are in integer representation (32 bits for IPv4 and 128 bits for IPv6).
You must recognize both the onward (e.g., <192.168.0.2><10.0.0.3>><20000><80>)
and returning (<10.0.0.3><192.168.0.2><80><20000>) packets as the same flow,
because these packets belong to the same TCP connection.
In the sample solution, [pcap_flow.py](./pcap_flow.py) consists of 66 lines
 (not provided, and this number of lines is just a reference, no
need to match). 


## Part 2: Identifying IPv4 sources that send a large amount of data (10%)

In this part of the assignment, you are asked to identify where the vast majority of the traffic comes from. To
this end, first, create a [binary search tree](https://en.wikipedia.org/wiki/Binary_search_tree)
whose nodes contain a source IPv4 address (ignore IPv6 packets for this
part of the assignment) and bytes sent (just use Total Length field in the IPv4 header).
After inserting all the nodes for the packet trace, merge the IPv4 sources which
have sent less than 5% of the total bytes counted in the tree into the parent
node, recursively from the bottom of the tree. You thus need to aggregate the
bytes sent and the IP address into the parent node.  If a node has less than 5%
of the traffic but its leaf(s) does not, aggregate bytes but leave the node
(e.g., second-top node in the right side of the picture below).
The IP address aggregated
can be represented in the form of a network address (e.g., `192.168.0.0/16`).
The figure below shows an example of before (left) and after (right) the
aggregation.  
![bintree](bintree.png)  
Do this task by completing the `add`, `data` and `aggr` methods and the `supernet` static method of the  
 `Node` class in [pcap_aggr.py](./pcap_aggr.py), so that the `Plot` method plots traffic volume
sent by the aggregated source addresses or networks. Do not remove any existing
lines.
You should be able to analyze and plot the data in [202201031400p.pcap.gz](202201031400p.pcap.gz.aggr.pdf) by:
```
python3 ./pcap_aggr.py 202201031400p.pcap.gz
```
You can use the small subset of the
dataset ([sample.pcap.gz](./sample.pcap.gz)) in the
development phase to speed up the cycle.
When you plot this small dataset with the correct code, it will look like
[sample.pcap.gz.aggr.correct.pdf](./sample.pcap.gz.aggr.correct.pdf).

### Marking Criteria

1. [pcap_aggr.py](./pcap_aggr.py) can generate a binary search tree by completing `add()` method in the `Node` class, which need to pass the following test (**4%**):
```
python3 -m pytest tests/test_pcap_aggr.py::test_pcap_aggr1
```
2. [pcap_aggr.py](./pcap_aggr.py) can aggregate the sources (tree nodes) based on the rule described above by completing `supernet()` and `aggr()` method in the `Node` class, and at least 50% of nodes correctly appear when processing [202201031400p.pcap.gz](./202201031400p.pcap.gz). Meeting this criteria must pass the following test (**4%**):
```
python3 -m pytest tests/test_pcap_aggr.py::test_pcap_aggr2
```

3. Same as above but all the nodes correctly appear, which must pass the following test (**2%**):
```
python3 -m pytest tests/test_pcap_aggr.py::test_pcap_aggr3
```
Note that since meeting the first criteria is an intermediate step to meet the second criteria, the possible score is 0%, 4%, 8% or 10%. As in Part 1, results of those tests are indicative but not a guarantee, and cheating will score 0%.

### Hints

The `add` method takes two arguments [`IPv4Address` object](https://docs.python.org/3/library/ipaddress.html)) that represents the IPv4 address and packet length.
It recursively traverses the tree down to a leaf, then inserts a new entry with the given
address and packet length.

`supernet` static method computes and returns the common network address and
mask ([`IPv4Network` object](https://docs.python.org/3/library/ipaddress.html))
of the two IPv4 addresses, each of which is either an `IPv4Address` or `IPv4Network` object.
For example, the common prefix of 192.168.1.3/32 and 192.161.56.1/32 is 192.160.0.0/12.
Note that an `IPv4Address` object can be converted to an `IPv4Network` object (e.g., `ip_network(ip_address('192.168.1.3'))` returns `IPv4Network('192.168.1.3/32')`). Once you obtain an `IPv4Network` object, you can extract the network address by the `.network_address` attribute (e.g., `ip_network(ip_address('192.168.1.3')).network_address`).

The `aggr` method takes the number of bytes to be aggregated as the argument
(e.g., 2000 means sources that transferred less than 2000 bytes are aggregated
into the parents nodes).
The `data` method takes a dictionary as the argument, and recursively traverses the tree and fill the dictionary with
`IPv4Network` objects as keys and the bytes sent as values.

After the completion, pcap_aggr.py consists of 107 lines in the
sample solution (not provided), but this number is just a reference, and no
need to match.

