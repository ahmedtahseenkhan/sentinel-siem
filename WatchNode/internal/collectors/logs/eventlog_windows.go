//go:build windows

package logs

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"github.com/watchnode/watchnode/internal/models"
	"golang.org/x/sys/windows"
)

// Windows Event Log API constants not in the windows package.
const (
	evtQueryChannelPath     = 0x1
	evtQueryForwardDirection = 0x100
	evtRenderEventXml       = 1
	evtSystemKeywords       = 0x400
	evtSystemTimeCreated    = 7
	evtSystemEventID        = 1
	evtSystemLevel          = 3
	evtSystemChannel        = 8
	evtSystemComputer       = 12

	readFlagsSequential = 0x1
	readFlagsTimeout    = 1000 // milliseconds
)

var (
	modwevtapi              = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery            = modwevtapi.NewProc("EvtQuery")
	procEvtNext             = modwevtapi.NewProc("EvtNext")
	procEvtCreateRenderContext = modwevtapi.NewProc("EvtCreateRenderContext")
	procEvtRender           = modwevtapi.NewProc("EvtRender")
	procEvtClose            = modwevtapi.NewProc("EvtClose")
	procEvtSubscribe        = modwevtapi.NewProc("EvtSubscribe")
)

type evtHandle uintptr

// runEventLog reads from one or more Windows Event Log channels using
// the EvtQuery/EvtNext/EvtRender API (wevtapi.dll).
// It first performs a historical backfill of recent events, then
// subscribes for real-time delivery using EvtSubscribe with EvtSubscribeToFutureEvents.
func runEventLog(ctx context.Context, channels []string, dataCh chan<- models.DataPoint, stopCh <-chan struct{}) {
	if len(channels) == 0 {
		channels = []string{"Security", "System", "Application"}
	}

	for _, ch := range channels {
		ch := ch
		go func() {
			runChannelLoop(ctx, ch, dataCh, stopCh)
		}()
	}

	// Block until stop/cancel.
	select {
	case <-ctx.Done():
	case <-stopCh:
	}
}

func runChannelLoop(ctx context.Context, channel string, dataCh chan<- models.DataPoint, stopCh <-chan struct{}) {
	// Build an XPath query that selects all events from the channel.
	query := "*"

	// Subscribe to future events so we never miss a record while the query catches up.
	signalEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		emitError(dataCh, channel, fmt.Sprintf("create signal event: %v", err))
		return
	}
	defer windows.CloseHandle(signalEvent)

	channelPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		emitError(dataCh, channel, fmt.Sprintf("utf16: %v", err))
		return
	}
	queryPtr, err := windows.UTF16PtrFromString(query)
	if err != nil {
		emitError(dataCh, channel, fmt.Sprintf("utf16: %v", err))
		return
	}

	// EvtSubscribe with EvtSubscribeToFutureEvents (flag=1).
	subHandle, _, _ := procEvtSubscribe.Call(
		0,
		uintptr(signalEvent),
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		0, 0, 0,
		1, // EvtSubscribeToFutureEvents
	)

	if subHandle == 0 {
		// Fall back to polling query if subscribe not available.
		pollChannel(ctx, channel, dataCh, stopCh)
		return
	}
	defer procEvtClose.Call(subHandle)

	// Pull events from subscription in a tight loop.
	for {
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		default:
		}

		pulled := pullEvents(evtHandle(subHandle), channel, dataCh)
		if pulled == 0 {
			// Wait for the signal event or poll timeout.
			evt, _ := windows.WaitForSingleObject(signalEvent, 500)
			if evt == windows.WAIT_OBJECT_0 {
				_ = windows.ResetEvent(signalEvent)
			}
		}
	}
}

// pollChannel is the fallback implementation using EvtQuery, used when subscribe is unavailable.
func pollChannel(ctx context.Context, channel string, dataCh chan<- models.DataPoint, stopCh <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	channelPtr, _ := windows.UTF16PtrFromString(channel)
	queryPtr, _ := windows.UTF16PtrFromString("*")

	for {
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		case <-ticker.C:
			qh, _, _ := procEvtQuery.Call(
				0,
				uintptr(unsafe.Pointer(channelPtr)),
				uintptr(unsafe.Pointer(queryPtr)),
				evtQueryChannelPath|evtQueryForwardDirection,
			)
			if qh == 0 {
				continue
			}
			pullEvents(evtHandle(qh), channel, dataCh)
			procEvtClose.Call(qh)
		}
	}
}

func pullEvents(handle evtHandle, channel string, dataCh chan<- models.DataPoint) int {
	const batchSize = 64
	handles := make([]evtHandle, batchSize)

	var returned uint32
	r, _, _ := procEvtNext.Call(
		uintptr(handle),
		batchSize,
		uintptr(unsafe.Pointer(&handles[0])),
		readFlagsTimeout,
		0,
		uintptr(unsafe.Pointer(&returned)),
	)
	if r == 0 || returned == 0 {
		return 0
	}

	for i := uint32(0); i < returned; i++ {
		dp := renderEvent(handles[i], channel)
		procEvtClose.Call(uintptr(handles[i]))
		if dp != nil {
			select {
			case dataCh <- *dp:
			default:
			}
		}
	}
	return int(returned)
}

func renderEvent(handle evtHandle, channel string) *models.DataPoint {
	// First call to get required buffer size.
	var bufSize, used, props uint32
	procEvtRender.Call(0, uintptr(handle), evtRenderEventXml, 0, 0,
		uintptr(unsafe.Pointer(&used)),
		uintptr(unsafe.Pointer(&props)),
	)
	if used == 0 {
		return nil
	}

	buf := make([]uint16, (used/2)+1)
	bufSize = uint32(len(buf) * 2)
	r, _, _ := procEvtRender.Call(0, uintptr(handle), evtRenderEventXml,
		uintptr(bufSize),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)),
		uintptr(unsafe.Pointer(&props)),
	)
	if r == 0 {
		return nil
	}

	xmlStr := windows.UTF16ToString(buf)

	// Extract key fields from XML using lightweight string scanning
	// to avoid importing encoding/xml (overhead) in a hot path.
	eventID := extractXMLField(xmlStr, "EventID")
	level := extractXMLField(xmlStr, "Level")
	computer := extractXMLField(xmlStr, "Computer")
	timeCreated := extractXMLAttr(xmlStr, "TimeCreated", "SystemTime")
	provider := extractXMLAttr(xmlStr, "Provider", "Name")
	message := extractXMLField(xmlStr, "Message")
	if message == "" {
		// Fall back to the raw Data field when RenderMessage is unavailable.
		message = extractXMLField(xmlStr, "Data")
	}

	ts := time.Now()
	if timeCreated != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, timeCreated); err == nil {
			ts = parsed
		}
	}

	// Build base fields.
	fields := map[string]interface{}{
		"channel":   channel,
		"event_id":  eventID,
		"level":     level,
		"computer":  computer,
		"provider":  provider,
		"message":   message,
		"raw_xml":   xmlStr,
	}

	// Extract numeric event ID and enrich with security metadata.
	numericID := extractEventID(xmlStr)
	fields["win_event_id"] = numericID

	desc := securityEventDescription(numericID)
	if desc != "" {
		fields["win_event_description"] = desc
		fields["win_security_relevant"] = true
	}

	// Extract all EventData Name/value pairs with win_ prefix.
	evData := extractEventData(xmlStr)
	for k, v := range evData {
		fields["win_"+k] = v
	}

	// Add human-readable logon type name if present.
	if lt, ok := evData["LogonType"]; ok && lt != "" {
		fields["win_logon_type_name"] = mapLogonType(lt)
	}

	return &models.DataPoint{
		Timestamp: ts,
		Type:      "log.eventlog",
		Fields:    fields,
		Tags: map[string]string{
			"source":  "eventlog",
			"channel": channel,
		},
	}
}

// extractEventData extracts all <Data Name="...">value</Data> elements from
// the EventData section and returns a map of Name → value. It also handles
// unnamed <Data>value</Data> elements, storing them under numeric keys
// ("0", "1", …).
func extractEventData(xmlStr string) map[string]string {
	result := make(map[string]string)
	// Find the EventData section.
	edStart := strings.Index(xmlStr, "<EventData>")
	if edStart == -1 {
		edStart = strings.Index(xmlStr, "<EventData ")
	}
	if edStart == -1 {
		return result
	}
	edEnd := strings.Index(xmlStr[edStart:], "</EventData>")
	if edEnd == -1 {
		return result
	}
	section := xmlStr[edStart : edStart+edEnd+len("</EventData>")]

	// Iterate over <Data ...> occurrences.
	pos := 0
	unnamedIdx := 0
	for {
		di := strings.Index(section[pos:], "<Data")
		if di == -1 {
			break
		}
		di += pos
		tagEnd := strings.Index(section[di:], ">")
		if tagEnd == -1 {
			break
		}
		tagEnd += di
		tag := section[di : tagEnd+1]

		// Extract the Name attribute if present.
		name := ""
		ni := strings.Index(tag, `Name="`)
		if ni != -1 {
			rest := tag[ni+6:]
			qi := strings.Index(rest, `"`)
			if qi != -1 {
				name = rest[:qi]
			}
		}
		if name == "" {
			name = fmt.Sprintf("%d", unnamedIdx)
			unnamedIdx++
		}

		// Find the closing </Data>.
		closeTag := "</Data>"
		closeStart := strings.Index(section[tagEnd+1:], closeTag)
		if closeStart == -1 {
			pos = tagEnd + 1
			continue
		}
		value := strings.TrimSpace(section[tagEnd+1 : tagEnd+1+closeStart])
		result[name] = value
		pos = tagEnd + 1 + closeStart + len(closeTag)
	}
	return result
}

// extractEventID parses and returns the integer EventID from the XML.
func extractEventID(xmlStr string) int {
	raw := extractXMLField(xmlStr, "EventID")
	if raw == "" {
		return 0
	}
	id := 0
	for _, ch := range raw {
		if ch >= '0' && ch <= '9' {
			id = id*10 + int(ch-'0')
		}
	}
	return id
}

// mapLogonType converts a numeric logon type string to a human-readable name.
func mapLogonType(logonType string) string {
	switch logonType {
	case "2":
		return "Interactive"
	case "3":
		return "Network"
	case "4":
		return "Batch"
	case "5":
		return "Service"
	case "7":
		return "Unlock"
	case "8":
		return "NetworkCleartext"
	case "9":
		return "NewCredentials"
	case "10":
		return "RemoteInteractive (RDP)"
	case "11":
		return "CachedInteractive"
	default:
		return logonType
	}
}

// securityEventDescription returns a human-readable description for common
// Windows Security Event IDs, or empty string if unknown.
func securityEventDescription(eventID int) string {
	switch eventID {
	case 4624:
		return "Successful logon"
	case 4625:
		return "Failed logon"
	case 4634:
		return "Logoff"
	case 4647:
		return "User-initiated logoff"
	case 4648:
		return "Logon with explicit credentials"
	case 4656:
		return "Handle to object requested"
	case 4663:
		return "Attempt to access object"
	case 4672:
		return "Special privileges assigned to new logon"
	case 4688:
		return "New process created"
	case 4698:
		return "Scheduled task created"
	case 4702:
		return "Scheduled task updated"
	case 4720:
		return "User account created"
	case 4722:
		return "User account enabled"
	case 4723:
		return "Password change attempted"
	case 4724:
		return "Password reset attempted"
	case 4725:
		return "User account disabled"
	case 4726:
		return "User account deleted"
	case 4728:
		return "Member added to global group"
	case 4732:
		return "Member added to local group"
	case 4738:
		return "User account changed"
	case 4740:
		return "User account locked out"
	case 4756:
		return "Member added to universal group"
	case 4768:
		return "Kerberos TGT requested"
	case 4769:
		return "Kerberos service ticket requested"
	case 4771:
		return "Kerberos pre-authentication failed"
	case 4776:
		return "NTLM authentication attempted"
	case 4778:
		return "Session reconnected to Window Station (RDP reconnect)"
	case 4779:
		return "Session disconnected from Window Station"
	case 7034:
		return "Service crashed"
	case 7036:
		return "Service state changed"
	case 7040:
		return "Service start type changed"
	case 7045:
		return "New service installed"
	default:
		return ""
	}
}

// securityRelevantEventIDs is the set of event IDs we consider security-relevant.
var securityRelevantEventIDs = map[int]struct{}{
	4624: {}, 4625: {}, 4634: {}, 4647: {}, 4648: {}, 4656: {}, 4663: {},
	4672: {}, 4688: {}, 4698: {}, 4702: {}, 4720: {}, 4722: {}, 4723: {},
	4724: {}, 4725: {}, 4726: {}, 4728: {}, 4732: {}, 4738: {}, 4740: {},
	4756: {}, 4768: {}, 4769: {}, 4771: {}, 4776: {}, 4778: {}, 4779: {},
	7034: {}, 7036: {}, 7040: {}, 7045: {},
}

// extractXMLField finds the text content of the first occurrence of <Tag>…</Tag>.
func extractXMLField(xml, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	start := strings.Index(xml, open)
	if start == -1 {
		// Try self-closing or with attributes.
		open2 := "<" + tag + " "
		start = strings.Index(xml, open2)
		if start == -1 {
			return ""
		}
		end := strings.Index(xml[start:], ">")
		if end == -1 {
			return ""
		}
		inner := xml[start+end+1:]
		endTag := strings.Index(inner, close)
		if endTag == -1 {
			return ""
		}
		return strings.TrimSpace(inner[:endTag])
	}
	inner := xml[start+len(open):]
	end := strings.Index(inner, close)
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(inner[:end])
}

// extractXMLAttr finds the value of an attribute within the first occurrence of <Tag attr="…">.
func extractXMLAttr(xml, tag, attr string) string {
	open := "<" + tag + " "
	start := strings.Index(xml, open)
	if start == -1 {
		return ""
	}
	end := strings.Index(xml[start:], ">")
	if end == -1 {
		return ""
	}
	fragment := xml[start : start+end]
	needle := attr + `="`
	ai := strings.Index(fragment, needle)
	if ai == -1 {
		return ""
	}
	rest := fragment[ai+len(needle):]
	qi := strings.Index(rest, `"`)
	if qi == -1 {
		return ""
	}
	return rest[:qi]
}

func emitError(dataCh chan<- models.DataPoint, channel, msg string) {
	select {
	case dataCh <- models.DataPoint{
		Timestamp: time.Now(),
		Type:      "log.eventlog.error",
		Fields:    map[string]interface{}{"message": msg, "channel": channel},
		Tags:      map[string]string{"source": "eventlog", "channel": channel},
	}:
	default:
	}
}
