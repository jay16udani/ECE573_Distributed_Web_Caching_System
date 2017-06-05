The package consists of two files l3_controller.py and TCPServer_thread.py. The 2 files have different functionalities each.

l3_controller.py :  The controller is built on top of pox framework and with its ability to capture events and callbacks from the switch. The pox controller framework is using the openflow model and architecture. The controller designed by us takes into account the IP from which the files are being requested and accordingly routes the requests to the appropriate cache. If the IP was not assigned the cache previously, we assign the cache using the round robin fashion. The routes to these cahces are dynalically learned by the switches using the controller. The pox controller uses the l3 packets and l2 packets to identify the destination, modify them, change checksum and further install flows onto the switch.

TCPServer_thread.py : The cache is built using python and uses TCP socket to stream the files back to the client. It is a persistemt cache and hence provides significant benefits in terms of reliablity. Even when the cache is restarted, it can return back to the previous state. The cache maintains persistence by saving the files and metadata in JSON files. The cache can accept TCP requests on the port 80. It can further determine of the files needs to be downloaded or can be servcied via the existing cache we maintain.


******************************************************** How to run ************************************************************

l3_controller.py :
				 1. install git using 'apt-get install git'
				 2. pull the latest repo for the pox controller.
				 3. Place out l3_controller in the pox/pox/forwarding directory.
				 4. using the command ./pox.py samples.pretty_log -log.level --DEBUG forwarding.l3_controller
				 5. The logs levels can be varied accordingly.

TCPServer_thread.py:
				 1. Copy the file into a directory names DistCache
				 2. Create directory called cache
				 3. Create directory called metadata
				 4. Note : The code does handle the missing directory conditions - safer to create them and give permissions.
				 5. Use the command sudo python TCPServer_thread.py as it needs access to port 80.


******************************************************* Environment Settings ****************************************************

1. The above files in specific just needs python.
2. Follow steps on the pox wiki to install pox controller.
3. Rest would be a straight forward approach of using our topology to login into the designated hosts to run the above commands.



******************************************************* Steps to run tests ****************************************************
1. Login into exogenie and into our topology
2. Login into C1 - client 1 nand C2 - client 2
3. Login into cache 1 and cache 2 - use the above mentioned TCPServer code and start the cache 
4. Login into controller and start the controller.
5. The from the client execute the below mentioned tests.

********************************************************** commands to use to run the test ******************************************************

1. time curl --interface eth1 http://www.unc.edu/~saraswat/teaching/econ870/fall11/NM_94.pdf  --local-port 12000 --output NM_94.pdf

2. time curl --interface eth1 http://www.iso.org/iso/annual_report_2009.pdf  --local-port 12000 --output report.pdf

3. time curl --interface eth1 http://imaging.nikon.com:80/lineup/lens/zoom/normalzoom/af-s_dx_18-140mmf_35-56g_ed_vr/img/sample/img_01.jpg  --local-port 12000 --output img_01.jpg

4. time curl --interface eth1 http://imaging.nikon.com/lineup/lens/zoom/normalzoom/af-s_dx_18-140mmf_35-56g_ed_vr/img/sample/img_02.jpg  --local-port 12000 --output img_02.jpg

5. time curl --interface eth1 http://www.boomerangphotography.com/data/storage/attachments/cde82f439cc712b59b2ff1d0e4c3890b.jpg --local-port 12000 --output img_03.jpg

************************************************************* interpretting the results **********************************************************

The output of the above commands will indicate the performance improvement in terms of when the files are being fetched from the inetrnet and when from the cache.

ex: 
real 2m7.262s - 
indicate the time taken by the linux kernel to complete excution and fetching the file. The performance will be low when its downloading the first time as its being downloaded from the internet. 

You can find more details in the repot with screen shots.













