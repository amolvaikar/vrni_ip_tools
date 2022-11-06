from diagrams import Cluster, Diagram
from diagrams.generic.network import Router
from diagrams.generic.network import Switches

with Diagram("test network map", show=True):
	r1 = Router("Cisco Router1")
	r2 = Router("Cisco Router2")

