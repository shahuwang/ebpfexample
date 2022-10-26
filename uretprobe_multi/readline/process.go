//go:build linux

package readline

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os/user"
	"strconv"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target native -type event bpf  uretprobe.c -- -I../../headers

const READLINE = "readline"

type Context struct {
	objs   bpfObjects
	uplink link.Link
	rd     *ringbuf.Reader
}

func (ctx *Context) Close() {
	ctx.objs.Close()
	ctx.uplink.Close()
	if ctx.rd != nil {
		ctx.rd.Close()
	}
}

func (ctx *Context) Loadbpf(binPath string) (err error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	objs := bpfObjects{}

	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
		return err
	}
	ctx.objs = objs
	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
		return err
	}
	up, err := ex.Uretprobe(READLINE, ctx.objs.UretprobeBashReadline, nil)
	if err != nil {
		log.Fatalf("creating uretprobe: %s", err)
		return err
	}
	ctx.uplink = up
	rd, err := ringbuf.NewReader(ctx.objs.Events)
	if err != nil {
		log.Fatalf("creating ringbuf event reader: %s", err)
		return err
	}
	ctx.rd = rd
	return nil
}

func (ctx *Context) ReadEvent() (event *bpfEvent, err error) {
	record, err := ctx.rd.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, nil
		}
		return nil, err
	}
	event = new(bpfEvent)
	err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, event)
	if err != nil {
		return nil, err
	}
	return event, nil
}

func (ctx *Context) PrintEvent(event *bpfEvent) {
	if event == nil {
		return
	}
	gid := event.Gid
	uid := strconv.Itoa(int(event.Uid))
	line := unix.ByteSliceToString(event.Line[:])
	group, _ := user.LookupGroupId(strconv.Itoa(int(gid)))
	userN, _ := user.LookupId(uid)
	log.Printf("cmd: %s, group name: %s, user name: %s", line, group.Name, userN.Username)
}
