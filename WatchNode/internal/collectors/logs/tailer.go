package logs

import (
	"bufio"
	"context"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/watchnode/watchnode/internal/models"
)

const defaultMaxLine = 1048576
const defaultMaxBuf = 10485760

type tailer struct {
	path      string
	tags      []string
	multiline *regexp.Regexp
	maxLine   int
	maxBuf    int
	file      *os.File
	reader    *bufio.Reader
}

func newTailer(path string, tags []string, multilinePattern string, maxLine, maxBuf int) *tailer {
	if maxLine <= 0 {
		maxLine = defaultMaxLine
	}
	if maxBuf <= 0 {
		maxBuf = defaultMaxBuf
	}
	var re *regexp.Regexp
	if multilinePattern != "" {
		re, _ = regexp.Compile(multilinePattern)
	}
	return &tailer{
		path:      path,
		tags:      tags,
		multiline: re,
		maxLine:   maxLine,
		maxBuf:    maxBuf,
	}
}

func (t *tailer) run(ctx context.Context, dataCh chan<- models.DataPoint, stopCh <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		default:
		}
		f, err := os.Open(t.path)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		stat, _ := f.Stat()
		size := stat.Size()
		if size > int64(t.maxBuf) {
			_, _ = f.Seek(size-int64(t.maxBuf), 0)
		}
		t.file = f
		t.reader = bufio.NewReaderSize(f, 65536)
		t.readLoop(ctx, dataCh, stopCh)
		_ = f.Close()
		time.Sleep(1 * time.Second)
	}
}

func (t *tailer) readLoop(ctx context.Context, dataCh chan<- models.DataPoint, stopCh <-chan struct{}) {
	tags := make(map[string]string)
	for _, tag := range t.tags {
		tags["source"] = tag
	}
	if len(tags) == 0 {
		tags["source"] = "log"
	}
	var line strings.Builder
	for {
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		default:
		}
		segment, err := t.reader.ReadBytes('\n')
		if err != nil {
			if len(segment) > 0 {
				line.Write(segment)
				if line.Len() >= t.maxLine {
					emitLog(dataCh, line.String(), tags)
					line.Reset()
				}
			}
			return
		}
		s := strings.TrimSuffix(string(segment), "\n")
		if t.multiline != nil && !t.multiline.MatchString(s) && line.Len() > 0 {
			line.WriteString("\n")
			line.WriteString(s)
			continue
		}
		if line.Len() > 0 {
			emitLog(dataCh, line.String(), tags)
			line.Reset()
		}
		line.WriteString(s)
		if t.multiline == nil || !t.multiline.MatchString(s) {
			emitLog(dataCh, line.String(), tags)
			line.Reset()
		}
	}
}

func emitLog(dataCh chan<- models.DataPoint, message string, tags map[string]string) {
	dp := models.DataPoint{
		Timestamp: time.Now(),
		Type:      "log",
		Tags:      tags,
		Fields:    map[string]interface{}{"message": message},
	}
	select {
	case dataCh <- dp:
	default:
	}
}

func (t *tailer) close() {
	if t.file != nil {
		_ = t.file.Close()
	}
}
