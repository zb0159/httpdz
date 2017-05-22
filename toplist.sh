#!/bin/sh

#comments 


for i in $(ps -ef |grep httpd  |awk '{print $2}');
	do
    	   v=${v}${i}"",;
		
	done
	echo "top -p "${v};
	
