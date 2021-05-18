# Port-Scanner-Detector
The program is written on python and is able to scan through more than 150 thousand packets, the algorithm works by going through each packet in pcap file and check for the following:1-    Is the packet malformed ethernet? 2-    Is the packet on the IP protocol?3-    Is the packet coming or send through TCP connection?4-    Is the packet coming from ICMP (ping) protocol?The program at the beginning will ask for the input PCap file location and once given it has a for loop function that will discard any packets which is malformed or not through ethernet IP connection and then at every instance a packet is detected to be using the TCP or ping protocol the function will store the type of each ip detected along with the ports if it was TCP connection and the duration of the packets by storing the packet number time snippet  


Recommended:
To run the .py code via IDE please do the following:
1- Download PyCharm Community Edition from https://www.jetbrains.com/pycharm/download/#section=mac or any IDE that suits you best
2- open the .py folder and run it
3- the code will ask for the location of a pcap file
4- once given the code will run and output the plot along with the description
5- open the HTML file to find the Chartsplease install libraries: 
pip install dpkt
pip install sockets
pip install os-sys
pip install numpy
pip install pandas
pip install seaborn