#! /bin/bash
cd uprobe && go generate
cd ../uretprobe && go generate
cd ../
go build .
sudo ./uprobe_multi