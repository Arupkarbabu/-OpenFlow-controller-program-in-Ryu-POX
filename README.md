# -OpenFlow-controller-program-in-Ryu-POX
Write a OpenFlow controller program in Ryu/POX to parse and display L2,L3,L4 source and destination addresses in controller logs. Use a tree topology with 3 switches (supporting OF v1.0 only) and 4 hosts


#controller command :
Ryu :ryu-manager source.py

#create the topology : 
sudo mn --topo=tree,2 --controller =remote
