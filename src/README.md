# Source Code for Project

[qos.ipynb](qos.ipynb) is the Jupyter notebook based upon "p4lang_tutorials.ipynb", provided by the FABRIC testbed, although extensive modifications have been made to it to run the Apache server, AStream, generate control plane commands to run on the P4 switches (used by "simple_switch_CLI", the control plane for BMv2). 

[basic.p4](basic.p4) is a simple P4 program that implements standard L3 routing, using longest prefix match on the destination IP address to determine the destination of the packets. 

[http.p4](http2.p4) is a more complex P4 program that uses the TCP source/destination port to distinguish HTTP/2 traffic from other kinds of traffic (which I call "cross-traffic" in the report). The intention is that the HTTP/2 traffic will be transmitted across a faster link, while all other traffic can be transmitted across a slower link. By splitting the traffic across two different links, we can reduce network congestion, and achieve better performance (higher average bitrate) on the streaming video.