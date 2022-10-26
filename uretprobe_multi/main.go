//go:build linux

package main

import (
	"log"
	"sync"

	"github.com/shahuwang/ebpfsample/uretprobe_multi/passwd"
	"github.com/shahuwang/ebpfsample/uretprobe_multi/readline"
)

func main() {
	uretCtx := new(readline.Context)
	err := uretCtx.Loadbpf("/bin/bash")
	if err != nil {
		log.Fatal("load readline failed, ", err.Error())
		return
	}
	defer uretCtx.Close()
	uCtx := new(passwd.Context)
	err = uCtx.Loadbpf("/usr/lib/x86_64-linux-gnu/libpam.so.0")
	if err != nil {
		log.Fatal("load pam get authtok failed, ", err.Error())
		return
	}
	defer uCtx.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go outputReadline(uretCtx, &wg)
	wg.Add(1)
	go outputPamAuthtok(uCtx, &wg)
	wg.Wait()
}

func outputReadline(uretCtx *readline.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		event, err := uretCtx.ReadEvent()
		if err != nil {
			log.Println("readine get err:", err.Error())
			return
		}
		if event == nil {
			return
		}
		uretCtx.PrintEvent(event)
	}
}

func outputPamAuthtok(uCtx *passwd.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		event, err := uCtx.ReadEvent()
		if err != nil {
			log.Println("get pam authtok get err:", err.Error())
			return
		}
		if event == nil {
			return
		}
		uCtx.PrintEvent(event)
	}
}
