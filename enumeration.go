package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/smb"
)

var errRPCDenied = errors.New("share enumeration denied")

type discoveredShare struct {
	Name, Type, Comment string
	Disk                bool
}

func enumerateShares(conn *smb.Connection, wire *boundedDialer, host string) ([]discoveredShare, error) {
	const pipeShare = "IPC$"
	if err := wire.arm(); err != nil {
		return nil, err
	}
	if err := conn.TreeConnect(pipeShare); err != nil {
		return nil, err
	}
	defer func() {
		if wire.arm() == nil {
			_ = conn.TreeDisconnect(pipeShare)
		}
	}()
	if err := wire.arm(); err != nil {
		return nil, err
	}
	// This duplex handle is exclusively to the existing RPC named pipe. It
	// carries NetShareEnum queries, never writes to a disk share.
	pipe, err := conn.OpenFileExt(pipeShare, "srvsvc", &smb.CreateReqOpts{
		OpLockLevel: smb.OpLockLevelNone, ImpersonationLevel: smb.ImpersonationLevelImpersonation,
		DesiredAccess: smb.FAccMaskFileReadData | smb.FAccMaskFileWriteData | smb.FAccMaskSynchronize,
		ShareAccess:   smb.FileShareRead | smb.FileShareWrite | smb.FileShareDelete,
		CreateDisp:    smb.FileOpen,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if wire.arm() == nil {
			_ = pipe.CloseFile()
		}
	}()
	transport, err := smbtransport.NewSMBTransport(pipe)
	if err != nil {
		return nil, err
	}
	if err := wire.arm(); err != nil {
		return nil, err
	}
	bound, err := dcerpc.Bind(transport, mssrvs.MSRPCUuidSrvSvc, 3, 0, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return nil, err
	}
	return enumeratePages(host, func(request []byte) ([]byte, error) {
		if err := wire.arm(); err != nil {
			return nil, err
		}
		return bound.MakeRequest(mssrvs.SrvSvcOpNetShareEnumAll, request)
	})
}

// Follow server pagination only; never guess share names or probe other hosts.
// Caps defend against a broken server keeping a supposedly read-only query alive.
func enumeratePages(host string, call func([]byte) ([]byte, error)) (shares []discoveredShare, err error) {
	shares = []discoveredShare{}
	seen := make(map[string]bool)
	seenResume := make(map[uint32]bool)
	request := mssrvs.NewNetShareEnumAllRequestExt(host, 1)
	for page := 0; page < 256; page++ {
		body, err := request.Marshal()
		if err != nil {
			return shares, err
		}
		response, err := call(body)
		if err != nil {
			return shares, err
		}
		var decoded mssrvs.NetShareEnumAllResponse
		if err := decoded.Unmarshal(response); err != nil {
			return shares, fmt.Errorf("decode share list: %w", err)
		}
		if decoded.WindowsError != 0 && decoded.WindowsError != 234 { // ERROR_MORE_DATA
			if decoded.WindowsError == 5 {
				return shares, errRPCDenied
			}
			return shares, fmt.Errorf("NetShareEnum returned Windows status %d", decoded.WindowsError)
		}
		if decoded.InfoStruct.Level != 1 {
			return shares, errors.New("server returned unexpected share information level")
		}
		if list := decoded.InfoStruct.Level1; list != nil {
			for _, share := range list.Buffer {
				key := strings.ToLower(share.Name)
				if seen[key] {
					continue
				}
				if len(shares) >= 16384 {
					return shares, errors.New("share enumeration exceeded 16384-share safety limit")
				}
				seen[key] = true
				kind := share.Type & 0xff
				typeName := map[uint32]string{0: "disk", 1: "printer", 2: "device", 3: "ipc"}[kind]
				if typeName == "" {
					typeName = "other"
				}
				shares = append(shares, discoveredShare{Name: share.Name, Type: typeName, Comment: share.Comment, Disk: kind == 0})
			}
		}
		if decoded.WindowsError == 0 {
			return shares, nil
		}
		if decoded.ResumeHandle == nil || *decoded.ResumeHandle == 0 || seenResume[*decoded.ResumeHandle] {
			return shares, errors.New("server returned a non-progressing share enumeration cursor")
		}
		seenResume[*decoded.ResumeHandle] = true
		request.ResumeHandle = decoded.ResumeHandle
	}
	return shares, errors.New("share enumeration exceeded 256-page safety limit")
}
