# ps4misc

misc ps4 stuff leeched from ps4sdk and ps4link


## if u want to run stuff outside the browser

place a loader in /data/rcved

export ps4ip=xxx.xxx.xxx.xxx

cd function_hook
make
./run.sh
cd shellcore_inject
make
./run.sh
press home and do something like opening a non-granted pkg

at this point the 2nd loader should be running

rerun the kernel hooks outside the browser
cd function_hook
./stage2.sh
