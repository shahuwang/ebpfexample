#! /bin/bash
cd passwd && go generate
cd ../readline && go generate
cd ../
go build .
sudo ./uretprobe_multi