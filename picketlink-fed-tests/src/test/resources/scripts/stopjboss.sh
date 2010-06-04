#!/bin/ksh
ps -u`whoami` -opid,comm,args | grep "org.jboss.Main" | awk '{ print $1 }' | xargs kill -9
