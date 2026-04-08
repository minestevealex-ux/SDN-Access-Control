# SDN-Access-Control
SDN-Based Access Control System 
Project Overview
This project implements an SDN based access control system using Mininet and the Ryu controller. The goal is to allow communication only between authorized hosts while blocking unauthorized traffic dynamically using OpenFlow rules.

Objective
Enforce network level access control. Allow only authorized host communication. Dynamically install flow rules using match action logic. Block unauthorized traffic at the switch level.

Key Concepts
Software Defined Networking, OpenFlow protocol, controller and switch interaction, flow rule installation, packet filtering.
Network Topology
One switch s1, three hosts h1, h2, h3, and a remote Ryu controller.

Technologies Used
Mininet, Ryu Controller, OpenFlow 1.3, Open vSwitch.

Setup and Execution
Run Controller
PYTHONPATH=~/ryu python3 ~/ryu/ryu/cmd/manager.py access_control.py
Start Mininet
sudo mn --topo single,3 --controller=remote,ip=127.0.0.1,port=6653 --switch ovsk,protocols=OpenFlow13

Testing and Results
Allowed Communication
h1 ping h2
Result: Successful communication with zero packet loss.

Blocked Communication
h1 ping h3
Result: Destination Host Unreachable with one hundred percent packet loss.

Flow Table Inspection
sh ovs-ofctl -O OpenFlow13 dump-flows s1
priority=10,ip,nw_src=10.0.0.1,nw_dst=10.0.0.3 actions=drop
Traffic from h1 to h3 is blocked at the switch level.

Performance Testing
Latency using ping is low after flow installation. The first packet is processed by the controller.
h2 iperf -s
h1 iperf -c h2

Controller Logic
The controller handles packet_in events, extracts source and destination IP addresses, checks against the block list, and installs forwarding or drop rules accordingly.

Validation and Testing
Multiple host combinations were tested. Only authorized communication was allowed. Blocked hosts remained inaccessible.
Observations
The first packet is handled by the controller. Subsequent packets are handled by the switch using installed flow rules. This improves efficiency.

Conclusion
The system demonstrates centralized control, dynamic flow rule installation, and effective access control enforcement. Unauthorized communication is blocked at the data plane.

References
Ryu documentation, Mininet documentation, OpenFlow specification.
