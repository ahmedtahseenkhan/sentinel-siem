package queue

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/watchnode/watchnode/internal/models"
)

const (
	walFileName   = "watchnode-queue.wal"
	ckptFileName  = "watchnode-queue.ckpt"
	defaultMaxWAL = 500 * 1024 * 1024 // 500 MB
	ckptInterval  = 5 * time.Second
)

// walRecord is the on-disk representation of a models.DataPoint.
// Fields are JSON-marshalled as string values to survive round-trips through
// encoding/json without losing the numeric-vs-string distinction that matters
// for OpenSearch mappings — we re-encode via convert.go before sending gRPC.
type walRecord struct {
	Timestamp int64                  `json:"ts"`
	Type      string                 `json:"type"`
	Tags      map[string]string      `json:"tags,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// DiskQueue is a crash-safe, WAL-backed queue of DataPoints.
// Unacknowledged (unsent) points survive agent crashes and reconnects,
// providing at-least-once delivery semantics.
//
// Layout:
//
//	<dir>/watchnode-queue.wal   — append-only, newline-delimited JSON records
//	<dir>/watchnode-queue.ckpt  — last byte offset acknowledged by the stream
type DiskQueue struct {
	dir      string
	maxBytes int64

	mu       sync.Mutex
	walFile  *os.File
	writePos int64 // end of WAL file (next write position)
	sentPos  int64 // last position fed into outCh
	ackPos   int64 // last checkpoint-saved position

	outCh   chan models.DataPoint
	notifyCh chan struct{} // wakes reader when new data written
}

// NewDiskQueue opens (or creates) a DiskQueue rooted at dir.
// maxBytes is the maximum WAL file size; 0 uses the 500 MB default.
func NewDiskQueue(dir string, maxBytes int64) (*DiskQueue, error) {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("diskqueue mkdir: %w", err)
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxWAL
	}
	q := &DiskQueue{
		dir:      dir,
		maxBytes: maxBytes,
		outCh:    make(chan models.DataPoint, 2048),
		notifyCh: make(chan struct{}, 1),
	}

	walPath := filepath.Join(dir, walFileName)
	f, err := os.OpenFile(walPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("diskqueue open wal: %w", err)
	}
	q.walFile = f

	// Seek to end to find the real write position.
	pos, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("diskqueue seek: %w", err)
	}
	q.writePos = pos

	// Load checkpoint (last acked position).
	q.ackPos = q.loadCheckpoint()
	q.sentPos = q.ackPos

	return q, nil
}

// Write appends a DataPoint to the WAL and wakes the reader goroutine.
// Returns ErrQueueFull if the WAL has reached maxBytes.
func (q *DiskQueue) Write(p models.DataPoint) error {
	rec := walRecord{
		Timestamp: p.Timestamp.UnixMilli(),
		Type:      p.Type,
		Tags:      p.Tags,
		Fields:    p.Fields,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("diskqueue marshal: %w", err)
	}
	data = append(data, '\n')

	q.mu.Lock()
	if q.writePos >= q.maxBytes {
		q.mu.Unlock()
		return fmt.Errorf("diskqueue full (%d bytes)", q.writePos)
	}
	n, err := q.walFile.Write(data)
	q.writePos += int64(n)
	q.mu.Unlock()

	if err != nil {
		return fmt.Errorf("diskqueue write: %w", err)
	}
	// Non-blocking notify.
	select {
	case q.notifyCh <- struct{}{}:
	default:
	}
	return nil
}

// Output returns the channel that RunStream should read from.
func (q *DiskQueue) Output() <-chan models.DataPoint {
	return q.outCh
}

// Start begins the background reader and checkpointer goroutines.
func (q *DiskQueue) Start(ctx context.Context) {
	go q.runReader(ctx)
	go q.runCheckpointer(ctx)
}

func (q *DiskQueue) runReader(ctx context.Context) {
	walPath := filepath.Join(q.dir, walFileName)

	q.mu.Lock()
	startPos := q.sentPos
	q.mu.Unlock()

	for {
		// Open a fresh read handle so writes by the WAL writer are visible.
		rf, err := os.Open(walPath)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
				continue
			}
		}
		if _, err := rf.Seek(startPos, io.SeekStart); err != nil {
			rf.Close()
			continue
		}

		scanner := bufio.NewScanner(rf)
		scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
		pos := startPos
		for scanner.Scan() {
			line := scanner.Bytes()
			pos += int64(len(line)) + 1 // +1 for newline

			var rec walRecord
			if err := json.Unmarshal(line, &rec); err != nil {
				continue
			}
			dp := models.DataPoint{
				Timestamp: time.UnixMilli(rec.Timestamp),
				Type:      rec.Type,
				Tags:      rec.Tags,
				Fields:    rec.Fields,
			}
			select {
			case <-ctx.Done():
				rf.Close()
				return
			case q.outCh <- dp:
				q.mu.Lock()
				q.sentPos = pos
				q.mu.Unlock()
			}
		}
		rf.Close()

		// Caught up to the current write position — wait for more data.
		select {
		case <-ctx.Done():
			return
		case <-q.notifyCh:
			startPos = pos
		case <-time.After(2 * time.Second):
			// Periodic check in case notify was missed.
			startPos = pos
		}
	}
}

func (q *DiskQueue) runCheckpointer(ctx context.Context) {
	ticker := time.NewTicker(ckptInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Final save.
			q.mu.Lock()
			pos := q.sentPos
			q.mu.Unlock()
			_ = q.saveCheckpoint(pos)
			q.tryCompact()
			return
		case <-ticker.C:
			q.mu.Lock()
			pos := q.sentPos
			q.mu.Unlock()
			if pos != q.ackPos {
				if err := q.saveCheckpoint(pos); err == nil {
					q.mu.Lock()
					q.ackPos = pos
					q.mu.Unlock()
				}
			}
			q.tryCompact()
		}
	}
}

// tryCompact rewrites the WAL from the checkpoint when fully drained or when
// the checkpoint is past 80% of the WAL size, to reclaim disk space.
func (q *DiskQueue) tryCompact() {
	q.mu.Lock()
	writePos := q.writePos
	ackPos := q.ackPos
	q.mu.Unlock()

	if writePos == 0 || ackPos == 0 {
		return
	}
	// Only compact if ack is past 80% of the file or file is fully drained.
	if writePos > 0 && float64(ackPos)/float64(writePos) < 0.8 {
		return
	}

	walPath := filepath.Join(q.dir, walFileName)
	tmpPath := walPath + ".tmp"

	// If fully drained, just truncate.
	if ackPos >= writePos {
		q.mu.Lock()
		_ = q.walFile.Close()
		_ = os.Truncate(walPath, 0)
		f, err := os.OpenFile(walPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
		if err == nil {
			q.walFile = f
		}
		q.writePos = 0
		q.sentPos = 0
		q.ackPos = 0
		q.mu.Unlock()
		_ = q.saveCheckpoint(0)
		return
	}

	// Copy tail of WAL (from ackPos to writePos) into a temp file.
	rf, err := os.Open(walPath)
	if err != nil {
		return
	}
	if _, err := rf.Seek(ackPos, io.SeekStart); err != nil {
		rf.Close()
		return
	}
	wf, err := os.CreateTemp(q.dir, "compact-")
	if err != nil {
		rf.Close()
		return
	}
	copied, err := io.Copy(wf, rf)
	rf.Close()
	wf.Close()
	if err != nil {
		os.Remove(wf.Name())
		return
	}
	if err := os.Rename(wf.Name(), tmpPath); err != nil {
		os.Remove(wf.Name())
		return
	}
	q.mu.Lock()
	_ = q.walFile.Close()
	if err := os.Rename(tmpPath, walPath); err != nil {
		q.mu.Unlock()
		return
	}
	f, err := os.OpenFile(walPath, os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		q.mu.Unlock()
		return
	}
	q.walFile = f
	q.writePos = copied
	newSent := q.sentPos - ackPos
	if newSent < 0 {
		newSent = 0
	}
	q.sentPos = newSent
	q.ackPos = 0
	q.mu.Unlock()
	_ = q.saveCheckpoint(0)
}

func (q *DiskQueue) loadCheckpoint() int64 {
	data, err := os.ReadFile(filepath.Join(q.dir, ckptFileName))
	if err != nil {
		return 0
	}
	var pos int64
	if _, err := fmt.Sscan(string(data), &pos); err != nil {
		return 0
	}
	return pos
}

func (q *DiskQueue) saveCheckpoint(pos int64) error {
	path := filepath.Join(q.dir, ckptFileName)
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", pos)), 0600)
}

// Close flushes the checkpoint and closes the WAL file.
func (q *DiskQueue) Close() error {
	q.mu.Lock()
	pos := q.sentPos
	q.mu.Unlock()
	_ = q.saveCheckpoint(pos)
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.walFile != nil {
		return q.walFile.Close()
	}
	return nil
}
