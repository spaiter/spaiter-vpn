package sniff

import (
	std_bufio "bufio"
	"context"
	"errors"
	"io"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/http"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	C "github.com/spaiter/spaiter-vpn/core/constant"
)

func HTTPHost(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	request, err := http.ReadRequest(std_bufio.NewReader(reader))
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return E.Cause1(ErrNeedMoreData, err)
		} else {
			return err
		}
	}
	metadata.Protocol = C.ProtocolHTTP
	metadata.Domain = M.ParseSocksaddr(request.Host).Fqdn
	return nil
}
